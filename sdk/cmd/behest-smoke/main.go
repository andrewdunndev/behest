// behest-smoke: end-to-end smoke test for a deployed behest broker.
//
// Usage:
//
//	export BEHEST_URL=https://behest.your-account.workers.dev
//	export BEHEST_KEY=your-master-key
//	go run ./sdk/cmd/behest-smoke
//
// The program creates a credential request and waits for fulfillment.
// On your laptop, the agent should show a notification. Fulfill it:
//
//	behest-agent fulfill <id>
//
// For a fully automated self-test (no agent needed):
//
//	go run ./sdk/cmd/behest-smoke --self-test
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	behest "gitlab.com/dunn.dev/behest/behest/sdk"
	"golang.org/x/crypto/nacl/box"
)

func main() {
	selfTest := flag.Bool("self-test", false, "Fulfill the request automatically (no agent needed)")
	flag.Parse()

	brokerURL := os.Getenv("BEHEST_URL")
	authToken := os.Getenv("BEHEST_KEY")

	if brokerURL == "" {
		fmt.Fprintln(os.Stderr, "BEHEST_URL not set")
		os.Exit(1)
	}
	if authToken == "" {
		fmt.Fprintln(os.Stderr, "BEHEST_KEY not set")
		os.Exit(1)
	}

	client := behest.NewClient(brokerURL)
	client.AuthToken = authToken

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Println("=== behest smoke test ===")
	fmt.Printf("Broker: %s\n\n", brokerURL)

	// Create a request
	req, err := client.CreateRequest(ctx,
		"smoke-test",
		"This is a test. Enter any value to verify the relay works.",
		"Type anything (e.g. 'hello') and press enter.",
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CreateRequest failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Request created: %s\n", req.ID)
	fmt.Printf("Expires: %s\n\n", req.ExpiresAt.Format(time.RFC3339))

	if *selfTest {
		fmt.Println("Self-test mode: fulfilling automatically...")
		go selfFulfill(ctx, brokerURL, authToken, req.ID)
	} else {
		fmt.Println("Waiting for fulfillment from the agent...")
		fmt.Printf("Run: behest-agent fulfill %s\n\n", req.ID)
	}

	// Wait for fulfillment
	credential, err := req.Wait(ctx, behest.DefaultPollInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== SUCCESS ===\n")
	fmt.Printf("Received credential: %q\n", string(credential))
	fmt.Println("Round-trip complete. E2E encryption verified.")
}

// selfFulfill simulates an agent: fetches the pending request, encrypts
// a test credential, and submits it. No real agent needed.
func selfFulfill(ctx context.Context, brokerURL, authToken, requestID string) {
	time.Sleep(2 * time.Second)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	auth := "Bearer " + authToken

	// Fetch pending to get the requester's public key
	pendingReq, _ := http.NewRequestWithContext(ctx, "GET", brokerURL+"/v1/requests/pending", nil)
	pendingReq.Header.Set("Authorization", auth)
	resp, err := httpClient.Do(pendingReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "self-fulfill: fetch pending failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var pending struct {
		Requests []struct {
			ID        string `json:"id"`
			PublicKey string `json:"public_key"`
		} `json:"requests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		fmt.Fprintf(os.Stderr, "self-fulfill: decode failed: %v\n", err)
		return
	}

	var pubKeyB64 string
	for _, r := range pending.Requests {
		if r.ID == requestID {
			pubKeyB64 = r.PublicKey
			break
		}
	}
	if pubKeyB64 == "" {
		fmt.Fprintf(os.Stderr, "self-fulfill: request %s not found in pending\n", requestID)
		return
	}

	pubBytes, _ := base64.RawURLEncoding.DecodeString(pubKeyB64)
	var requesterPub [32]byte
	copy(requesterPub[:], pubBytes)

	agentPub, agentPriv, _ := box.GenerateKey(rand.Reader)
	testCredential := []byte("smoke-test-credential-ok")

	var nonce [24]byte
	rand.Read(nonce[:])
	ciphertext := box.Seal(nil, testCredential, &nonce, &requesterPub, agentPriv)

	body, _ := json.Marshal(map[string]string{
		"nonce":            base64.RawURLEncoding.EncodeToString(nonce[:]),
		"ciphertext":       base64.RawURLEncoding.EncodeToString(ciphertext),
		"agent_public_key": base64.RawURLEncoding.EncodeToString(agentPub[:]),
	})

	fulfillReq, _ := http.NewRequestWithContext(ctx, "POST",
		brokerURL+"/v1/requests/"+requestID+"/fulfill",
		bytes.NewReader(body))
	fulfillReq.Header.Set("Content-Type", "application/json")
	fulfillReq.Header.Set("Authorization", auth)

	fulfillResp, err := httpClient.Do(fulfillReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "self-fulfill: POST failed: %v\n", err)
		return
	}
	fulfillResp.Body.Close()

	if fulfillResp.StatusCode != 204 {
		fmt.Fprintf(os.Stderr, "self-fulfill: expected 204, got %d\n", fulfillResp.StatusCode)
	}
}
