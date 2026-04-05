// Package behest provides a Go client for the behest credential relay.
//
// A requesting service generates an ephemeral X25519 keypair, posts a
// credential request to the broker, and polls until a human fulfills it.
// The credential is end-to-end encrypted; the broker never sees plaintext.
package behest

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Client talks to a behest broker.
type Client struct {
	BrokerURL  string
	HTTPClient *http.Client
}

// NewClient creates a Client for the given broker URL.
func NewClient(brokerURL string) *Client {
	return &Client{
		BrokerURL: brokerURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Request represents a credential request in flight.
type Request struct {
	ID         string
	ExpiresAt  time.Time
	PublicKey  *[32]byte // requester's ephemeral public key
	PrivateKey *[32]byte // requester's ephemeral private key
	client     *Client
}

// CreateRequest posts a new credential request to the broker.
func (c *Client) CreateRequest(service, message, hint string) (*Request, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"service":    service,
		"message":    message,
		"hint":       hint,
		"public_key": base64.RawURLEncoding.EncodeToString(pub[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.HTTPClient.Post(
		c.BrokerURL+"/v1/requests",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("posting request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, readError(resp)
	}

	var result struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parsing expires_at: %w", err)
	}

	return &Request{
		ID:         result.ID,
		ExpiresAt:  expiresAt,
		PublicKey:  pub,
		PrivateKey: priv,
		client:     c,
	}, nil
}

// PollResult is returned by Poll when the request has been fulfilled.
type PollResult struct {
	Credential []byte
}

// Poll checks the broker for a fulfilled credential. Returns nil, nil if
// still pending. Returns a PollResult when fulfilled. Returns an error on
// expiry, network failure, or decryption failure.
func (r *Request) Poll() (*PollResult, error) {
	resp, err := r.client.HTTPClient.Get(
		r.client.BrokerURL + "/v1/requests/" + r.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("polling: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("request expired or not found")
	}
	if resp.StatusCode == http.StatusGone {
		return nil, fmt.Errorf("request already consumed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var result struct {
		Status     string `json:"status"`
		Credential *struct {
			Nonce          string `json:"nonce"`
			Ciphertext     string `json:"ciphertext"`
			AgentPublicKey string `json:"agent_public_key"`
		} `json:"credential"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if result.Status != "fulfilled" || result.Credential == nil {
		return nil, nil // still pending
	}

	// Decode the encrypted credential
	nonce, err := base64.RawURLEncoding.DecodeString(result.Credential.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(result.Credential.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	agentPub, err := base64.RawURLEncoding.DecodeString(result.Credential.AgentPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding agent public key: %w", err)
	}

	if len(nonce) != 24 {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	if len(agentPub) != 32 {
		return nil, fmt.Errorf("invalid agent public key length: %d", len(agentPub))
	}

	var nonceArr [24]byte
	copy(nonceArr[:], nonce)
	var agentPubArr [32]byte
	copy(agentPubArr[:], agentPub)

	plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &agentPubArr, r.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return &PollResult{Credential: plaintext}, nil
}

// Wait polls until the request is fulfilled or expires.
func (r *Request) Wait(interval time.Duration) ([]byte, error) {
	for {
		result, err := r.Poll()
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result.Credential, nil
		}
		if time.Now().After(r.ExpiresAt) {
			return nil, fmt.Errorf("request expired")
		}
		time.Sleep(interval)
	}
}

// Cancel deletes a pending request from the broker.
func (r *Request) Cancel() error {
	req, err := http.NewRequest(
		http.MethodDelete,
		r.client.BrokerURL+"/v1/requests/"+r.ID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("creating cancel request: %w", err)
	}

	resp, err := r.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("canceling: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return readError(resp)
	}
	return nil
}

func readError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("broker returned %d: %s", resp.StatusCode, string(body))
}
