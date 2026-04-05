package behest_test

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/dunn.dev/behest/behest/sdk"
)

func Example() {
	ctx := context.Background()
	client := behest.NewClient("https://behest.example.workers.dev")

	// Create a credential request
	req, err := client.CreateRequest(ctx,
		"my-app",
		"Need API token for deployment",
		"Log in to app.example.com, go to Settings > API Keys, copy the production key",
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Request %s created, expires at %s\n", req.ID, req.ExpiresAt.Format(time.RFC3339))
	fmt.Println("Waiting for a human to fulfill the request...")

	// Wait for fulfillment (polls every 2 seconds, cancelable via context)
	credential, err := req.Wait(ctx, 2*time.Second)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Got credential: %s\n", string(credential))
}
