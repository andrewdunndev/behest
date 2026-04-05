package behest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// mockBroker is an in-memory implementation of the behest broker for testing.
type mockBroker struct {
	mu       sync.Mutex
	requests map[string]*mockRequest
}

type mockRequest struct {
	ID         string      `json:"id"`
	Service    string      `json:"service"`
	Message    string      `json:"message"`
	Hint       string      `json:"hint"`
	PublicKey  string      `json:"public_key"`
	Status     string      `json:"status"`
	ExpiresAt  string      `json:"expires_at"`
	Credential *credential `json:"credential,omitempty"`
}

type credential struct {
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	AgentPubKey   string `json:"agent_public_key"`
}

func newMockBroker() *mockBroker {
	return &mockBroker{
		requests: make(map[string]*mockRequest),
	}
}

func (b *mockBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/requests":
		b.handleCreate(w, r)
	case r.Method == "GET" && len(r.URL.Path) > len("/v1/requests/"):
		id := r.URL.Path[len("/v1/requests/"):]
		if id == "pending" {
			b.handlePending(w, r)
			return
		}
		b.handleGet(w, r, id)
	case r.Method == "POST" && len(r.URL.Path) > len("/v1/requests/"):
		// /v1/requests/{id}/fulfill
		parts := r.URL.Path[len("/v1/requests/"):]
		id := parts[:36] // UUID length
		b.handleFulfill(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (b *mockBroker) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service   string `json:"service"`
		Message   string `json:"message"`
		Hint      string `json:"hint"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	id := "test-" + time.Now().Format("150405.000")

	b.mu.Lock()
	b.requests[id] = &mockRequest{
		ID:        id,
		Service:   body.Service,
		Message:   body.Message,
		Hint:      body.Hint,
		PublicKey:  body.PublicKey,
		Status:    "pending",
		ExpiresAt: time.Now().Add(10 * time.Minute).Format(time.RFC3339),
	}
	b.mu.Unlock()

	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         id,
		"expires_at": time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		"status":     "pending",
	})
}

func (b *mockBroker) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	b.mu.Lock()
	req, ok := b.requests[id]
	b.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	resp := map[string]interface{}{
		"id":         req.ID,
		"service":    req.Service,
		"message":    req.Message,
		"status":     req.Status,
		"expires_at": req.ExpiresAt,
	}

	if req.Status == "fulfilled" && req.Credential != nil {
		resp["credential"] = req.Credential
		// Single-use: delete after retrieval
		b.mu.Lock()
		delete(b.requests, id)
		b.mu.Unlock()
	}

	json.NewEncoder(w).Encode(resp)
}

func (b *mockBroker) handleFulfill(w http.ResponseWriter, r *http.Request, id string) {
	b.mu.Lock()
	req, ok := b.requests[id]
	b.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	var body credential
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	b.mu.Lock()
	req.Status = "fulfilled"
	req.Credential = &body
	b.mu.Unlock()

	w.WriteHeader(204)
}

func (b *mockBroker) handlePending(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	var pending []mockRequest
	for _, req := range b.requests {
		if req.Status == "pending" {
			pending = append(pending, *req)
		}
	}
	b.mu.Unlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": pending,
	})
}

func TestFullRoundTrip(t *testing.T) {
	broker := newMockBroker()
	server := httptest.NewServer(broker)
	defer server.Close()

	client := NewClient(server.URL)

	// 1. SDK creates a request (generates keypair, posts to broker)
	req, err := client.CreateRequest("test-service", "Need a token", "Go to example.com and copy the API key")
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	t.Logf("Request created: id=%s", req.ID)

	// 2. Verify the request is pending
	result, err := req.Poll()
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if result != nil {
		t.Fatal("Expected nil result for pending request")
	}

	// 3. Simulate the agent: fetch the pending request, get the public key
	broker.mu.Lock()
	storedReq := broker.requests[req.ID]
	requesterPubKeyB64 := storedReq.PublicKey
	broker.mu.Unlock()

	// Decode the requester's public key
	requesterPubBytes, err := base64.RawURLEncoding.DecodeString(requesterPubKeyB64)
	if err != nil {
		t.Fatalf("Failed to decode requester public key: %v", err)
	}
	var requesterPub [32]byte
	copy(requesterPub[:], requesterPubBytes)

	// 4. Agent generates its own keypair and encrypts the credential
	agentPub, agentPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Agent keypair generation failed: %v", err)
	}

	secretCredential := []byte("super-secret-api-token-12345")

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("Nonce generation failed: %v", err)
	}

	ciphertext := box.Seal(nil, secretCredential, &nonce, &requesterPub, agentPriv)

	// 5. Agent fulfills the request (posts encrypted credential to broker)
	broker.mu.Lock()
	storedReq.Status = "fulfilled"
	storedReq.Credential = &credential{
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce[:]),
		Ciphertext:  base64.RawURLEncoding.EncodeToString(ciphertext),
		AgentPubKey: base64.RawURLEncoding.EncodeToString(agentPub[:]),
	}
	broker.mu.Unlock()

	// 6. SDK polls and gets the fulfilled credential, decrypts it
	result, err = req.Poll()
	if err != nil {
		t.Fatalf("Poll after fulfillment failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result after fulfillment")
	}

	// 7. Verify the decrypted credential matches
	if string(result.Credential) != string(secretCredential) {
		t.Fatalf("Credential mismatch: got %q, want %q", result.Credential, secretCredential)
	}

	t.Logf("Round-trip successful: credential decrypted correctly")

	// 8. Verify the broker no longer has the request (single-use)
	broker.mu.Lock()
	_, exists := broker.requests[req.ID]
	broker.mu.Unlock()
	if exists {
		t.Fatal("Request should have been deleted after retrieval (single-use)")
	}
}

func TestBrokerNeverSeesPlaintext(t *testing.T) {
	broker := newMockBroker()
	server := httptest.NewServer(broker)
	defer server.Close()

	client := NewClient(server.URL)

	req, err := client.CreateRequest("test-service", "Need a secret", "")
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	// Simulate agent fulfillment
	broker.mu.Lock()
	storedReq := broker.requests[req.ID]
	requesterPubBytes, _ := base64.RawURLEncoding.DecodeString(storedReq.PublicKey)
	var requesterPub [32]byte
	copy(requesterPub[:], requesterPubBytes)
	broker.mu.Unlock()

	agentPub, agentPriv, _ := box.GenerateKey(rand.Reader)
	secret := []byte("my-plaintext-secret")

	var nonce [24]byte
	rand.Read(nonce[:])
	ciphertext := box.Seal(nil, secret, &nonce, &requesterPub, agentPriv)

	// Verify: the ciphertext stored at the broker does NOT contain the plaintext
	ciphertextStr := base64.RawURLEncoding.EncodeToString(ciphertext)
	if ciphertextStr == base64.RawURLEncoding.EncodeToString(secret) {
		t.Fatal("Ciphertext should not equal plaintext encoding")
	}

	// The raw bytes of the ciphertext should not contain the plaintext bytes
	for i := 0; i <= len(ciphertext)-len(secret); i++ {
		match := true
		for j := 0; j < len(secret); j++ {
			if ciphertext[i+j] != secret[j] {
				match = false
				break
			}
		}
		if match {
			t.Fatal("Plaintext found in ciphertext — encryption is broken")
		}
	}

	// Fulfill and verify decryption works
	broker.mu.Lock()
	storedReq.Status = "fulfilled"
	storedReq.Credential = &credential{
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce[:]),
		Ciphertext:  ciphertextStr,
		AgentPubKey: base64.RawURLEncoding.EncodeToString(agentPub[:]),
	}
	broker.mu.Unlock()

	result, err := req.Poll()
	if err != nil {
		t.Fatalf("Poll failed: %v", err)
	}
	if string(result.Credential) != string(secret) {
		t.Fatalf("Decryption failed: got %q, want %q", result.Credential, secret)
	}
}
