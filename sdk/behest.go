// Package behest provides a Go client for the behest credential relay.
//
// A requesting service generates an ephemeral X25519 keypair, posts a
// credential request to the broker, and polls until a human fulfills it.
// The credential is end-to-end encrypted; the broker never sees plaintext.
package behest

import (
	"bytes"
	"context"
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
	publicKey  *[32]byte // requester's ephemeral public key
	privateKey *[32]byte // requester's ephemeral private key
	client     *Client
}

// CreateRequest posts a new credential request to the broker.
func (c *Client) CreateRequest(ctx context.Context, service, message, hint string) (*Request, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BrokerURL+"/v1/requests", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
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
		publicKey:  pub,
		privateKey: priv,
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
func (r *Request) Poll(ctx context.Context) (*PollResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.client.BrokerURL+"/v1/requests/"+r.ID, nil)
	if err != nil {
		return nil, fmt.Errorf("creating poll request: %w", err)
	}

	resp, err := r.client.HTTPClient.Do(req)
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

	plaintext, err := r.decrypt(result.Credential.Nonce, result.Credential.Ciphertext, result.Credential.AgentPublicKey)
	if err != nil {
		return nil, err
	}

	return &PollResult{Credential: plaintext}, nil
}

func (r *Request) decrypt(nonceB64, ciphertextB64, agentPubB64 string) ([]byte, error) {
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	agentPub, err := base64.RawURLEncoding.DecodeString(agentPubB64)
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

	plaintext, ok := box.Open(nil, ciphertext, &nonceArr, &agentPubArr, r.privateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	// Zero the private key after successful decryption
	for i := range r.privateKey {
		r.privateKey[i] = 0
	}

	return plaintext, nil
}

// Wait polls until the request is fulfilled, the context is canceled, or the
// request expires. Returns the decrypted credential on success.
func (r *Request) Wait(ctx context.Context, interval time.Duration) ([]byte, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		result, err := r.Poll(ctx)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result.Credential, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(r.ExpiresAt) {
				return nil, fmt.Errorf("request expired")
			}
		}
	}
}

// Cancel deletes a pending request from the broker.
func (r *Request) Cancel(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		r.client.BrokerURL+"/v1/requests/"+r.ID, nil)
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
