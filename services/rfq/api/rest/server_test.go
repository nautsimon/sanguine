package rest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	apiClient "github.com/synapsecns/sanguine/services/rfq/api/client"
	"github.com/synapsecns/sanguine/services/rfq/api/db"
	"github.com/synapsecns/sanguine/services/rfq/api/rest"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/synapsecns/sanguine/ethergo/signer/wallet"
	"github.com/synapsecns/sanguine/services/rfq/api/model"
	"github.com/synapsecns/sanguine/services/rfq/relayer/relapi"
)

func (c *ServerSuite) TestNewQuoterAPIServer() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()
	client := &http.Client{}
	req, err := http.NewRequestWithContext(c.GetTestContext(), http.MethodGet, fmt.Sprintf("http://localhost:%d/quotes", c.port), nil)
	c.Require().NoError(err)
	resp, err := client.Do(req)
	c.Require().NoError(err)
	defer func() {
		err = resp.Body.Close()
		c.Require().NoError(err)
	}()
	c.Equal(http.StatusOK, resp.StatusCode)
	c.GetTestContext().Done()
}

// TestEIP191_SuccessfulSignature tests the EIP191 signature process for successful authentication.
func (c *ServerSuite) TestEIP191_SuccessfulSignature() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()

	// Prepare the authorization header with a signed timestamp.
	header, err := c.prepareAuthHeader(c.testWallet)
	if err != nil {
		c.Error(err)
		return
	}

	// Perform a PUT request to the API server with the authorization header.
	resp, err := c.sendPutQuoteRequest(header)
	if err != nil {
		c.Error(err)
		return
	}
	defer func() {
		err = resp.Body.Close()
		c.Require().NoError(err)
	}()

	// Log the response body for debugging.
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))

	// Assert that the response status code is HTTP 200 OK.
	c.Equal(http.StatusOK, resp.StatusCode)
}

// TestEIP191_UnsuccessfulSignature tests the EIP191 signature process with an incorrect wallet signature.
func (c *ServerSuite) TestEIP191_UnsuccessfulSignature() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()

	// Prepare the authorization header with a signed timestamp using an incorrect wallet.
	randomWallet, err := wallet.FromRandom()
	c.Require().NoError(err)
	header, err := c.prepareAuthHeader(randomWallet)
	if err != nil {
		c.Error(err)
		return
	}

	// Perform a PUT request to the API server with the incorrect authorization header.
	resp, err := c.sendPutQuoteRequest(header)
	if err != nil {
		c.Error(err)
		return
	}
	defer func() {
		err = resp.Body.Close()
		c.Require().NoError(err)
	}()
	// Log the response body for debugging.
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))

	// Assert that the response status code is HTTP 400 Bad Request.
	c.Equal(http.StatusBadRequest, resp.StatusCode)
}

// TestEIP191_SuccessfulPutSubmission tests a successful PUT request submission.
func (c *ServerSuite) TestEIP191_SuccessfulPutSubmission() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()

	// Prepare the authorization header with a signed timestamp.
	header, err := c.prepareAuthHeader(c.testWallet)
	c.Require().NoError(err)

	// Perform a PUT request to the API server with the authorization header.
	resp, err := c.sendPutQuoteRequest(header)
	c.Require().NoError(err)
	defer func() {
		_ = resp.Body.Close()
	}()

	// Log the response body for debugging.
	body, err := io.ReadAll(resp.Body)
	c.Require().NoError(err)
	fmt.Println(string(body))

	// Assert that the response status code is HTTP 200 OK.
	c.Assert().Equal(http.StatusOK, resp.StatusCode)
}

func (c *ServerSuite) TestPutAndGetQuote() {
	c.startQuoterAPIServer()

	header, err := c.prepareAuthHeader(c.testWallet)
	c.Require().NoError(err)

	// Send PUT request
	putResp, err := c.sendPutQuoteRequest(header)
	c.Require().NoError(err)
	defer func() {
		err = putResp.Body.Close()
		c.Require().NoError(err)
	}()
	c.Assert().Equal(http.StatusOK, putResp.StatusCode)

	// Send GET request to verify the PUT
	client := &http.Client{}
	req, err := http.NewRequestWithContext(c.GetTestContext(), http.MethodGet, fmt.Sprintf("http://localhost:%d/quotes?originChainId=1&originTokenAddr=0xOriginTokenAddrdestChainId=42161&destTokenAddr=0xDestTokenAddr", c.port), nil)
	c.Require().NoError(err)

	getResp, err := client.Do(req)
	c.Require().NoError(err)
	defer func() {
		_ = getResp.Body.Close()
	}()
	c.Assert().Equal(http.StatusOK, getResp.StatusCode)

	var quotes []*model.GetQuoteResponse
	err = json.NewDecoder(getResp.Body).Decode(&quotes)
	c.Require().NoError(err)

	// Check if the newly added quote is present
	found := false
	for _, q := range quotes {
		if q.FixedFee == "10" {
			found = true
			break
		}
	}
	c.Assert().True(found, "Newly added quote not found")
}

func (c *ServerSuite) TestPutAndGetQuoteByRelayer() {
	c.startQuoterAPIServer()

	header, err := c.prepareAuthHeader(c.testWallet)
	c.Require().NoError(err)

	// Send PUT request
	putResp, err := c.sendPutQuoteRequest(header)
	c.Require().NoError(err)
	defer func() {
		err = putResp.Body.Close()
		c.Require().NoError(err)
	}()
	c.Assert().Equal(http.StatusOK, putResp.StatusCode)

	// Send GET request to verify the PUT
	client := &http.Client{}
	req, err := http.NewRequestWithContext(c.GetTestContext(), http.MethodGet, fmt.Sprintf("http://localhost:%d/quotes?relayerAddress=%s", c.port, c.testWallet.Address().Hex()), nil)
	c.Require().NoError(err)

	getResp, err := client.Do(req)
	c.Require().NoError(err)
	defer func() {
		_ = getResp.Body.Close()
	}()
	c.Assert().Equal(http.StatusOK, getResp.StatusCode)

	var quotes []*model.GetQuoteResponse
	err = json.NewDecoder(getResp.Body).Decode(&quotes)
	c.Require().NoError(err)

	// Check if the newly added quote is present
	found := false
	for _, q := range quotes {
		if q.FixedFee == "10" {
			found = true
			break
		}
	}
	c.Assert().True(found, "Newly added quote not found")
}

func (c *ServerSuite) TestMultiplePutRequestsWithIncorrectAuth() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()

	// Create a random wallet for incorrect authorization
	randomWallet, err := wallet.FromRandom()
	c.Require().NoError(err)

	// Prepare the authorization header with a signed timestamp using the incorrect wallet
	header, err := c.prepareAuthHeader(randomWallet)
	c.Require().NoError(err)

	// Perform multiple PUT requests to the API server with the incorrect authorization header
	for i := 0; i < 3; i++ {
		resp, err := c.sendPutQuoteRequest(header)
		c.Require().NoError(err)
		defer func() {
			err = resp.Body.Close()
			c.Require().NoError(err)
		}()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		c.Require().NoError(err)

		// Log the response body for debugging
		fmt.Printf("Request %d response: Status: %d, Body: %s\n", i+1, resp.StatusCode, string(body))

		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			// These are acceptable error status codes for failed authentication
			c.Assert().True(true, "Request %d correctly failed with status %d", i+1, resp.StatusCode)
		case http.StatusOK:
			// The ModifyQuote method returns 200 OK with an empty body on success
			c.Assert().Empty(string(body), "Request %d should return an empty body on success", i+1)

			// Since this shouldn't happen with incorrect auth, fail the test
			c.Fail("Request %d unexpectedly succeeded, while submitting incorrect authentication", i+1)
		default:
			c.Fail("Unexpected status code %d for request %d", resp.StatusCode, i+1)
		}
	}
}

func (c *ServerSuite) TestFilterQuoteAge() {
	now := time.Now()

	// insert quote outside age range
	quotes := []*db.Quote{
		{OriginChainID: 1, UpdatedAt: now.Add(-time.Hour)},
		{OriginChainID: 2, UpdatedAt: now.Add(-time.Minute)},
	}

	filteredQuotes := rest.FilterQuoteAge(c.cfg, quotes)

	// verify old quote is filtered out
	c.Equal(1, len(filteredQuotes))
	c.Equal(quotes[1], filteredQuotes[0])
}

func (c *ServerSuite) TestPutAck() {
	c.startQuoterAPIServer()

	// Send GET request
	testTxID := "0x123"
	header, err := c.prepareAuthHeader(c.testWallet)
	c.Require().NoError(err)
	resp, err := c.sendPutAckRequest(header, testTxID)
	c.Require().NoError(err)
	c.Equal(http.StatusOK, resp.StatusCode)

	// Expect ack with shouldRelay=true
	var result relapi.PutRelayAckResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	c.Require().NoError(err)
	expectedResult := relapi.PutRelayAckResponse{
		TxID:           testTxID,
		ShouldRelay:    true,
		RelayerAddress: c.testWallet.Address().Hex(),
	}
	c.Equal(expectedResult, result)
	err = resp.Body.Close()
	c.Require().NoError(err)

	// Send another request with same txID
	header, err = c.prepareAuthHeader(c.testWallet)
	c.Require().NoError(err)
	resp, err = c.sendPutAckRequest(header, testTxID)
	c.Require().NoError(err)
	c.Equal(http.StatusOK, resp.StatusCode)

	// Expect ack with shouldRelay=true
	err = json.NewDecoder(resp.Body).Decode(&result)
	c.Require().NoError(err)
	expectedResult = relapi.PutRelayAckResponse{
		TxID:           testTxID,
		ShouldRelay:    true,
		RelayerAddress: c.testWallet.Address().Hex(),
	}
	c.Equal(expectedResult, result)
	err = resp.Body.Close()
	c.Require().NoError(err)
	c.GetTestContext().Done()
}

// startQuoterAPIServer starts the API server and waits for it to initialize.
func (c *ServerSuite) startQuoterAPIServer() {
	go func() {
		err := c.QuoterAPIServer.Run(c.GetTestContext())
		c.Require().NoError(err)
	}()
	time.Sleep(2 * time.Second) // Wait for the server to start.
}

// prepareAuthHeader generates an authorization header using EIP191 signature with the given private key.
func (c *ServerSuite) prepareAuthHeader(wallet wallet.Wallet) (string, error) {
	// Get the current Unix timestamp as a string.
	now := strconv.Itoa(int(time.Now().Unix()))

	// Prepare the data to be signed.
	data := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(now)) + now
	digest := crypto.Keccak256([]byte(data))

	// Sign the data with the provided private key.
	sig, err := crypto.Sign(digest, wallet.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}
	signature := hexutil.Encode(sig)

	// Return the combined header value.
	return now + ":" + signature, nil
}

// sendPutQuoteRequest sends a PUT request to the server with the given authorization header.
func (c *ServerSuite) sendPutQuoteRequest(header string) (*http.Response, error) {
	// Prepare the PUT request with JSON data.
	client := &http.Client{}
	putData := model.PutQuoteRequest{
		OriginChainID:   1,
		OriginTokenAddr: "0xOriginTokenAddr",
		DestChainID:     42161,
		DestTokenAddr:   "0xDestTokenAddr",
		DestAmount:      "100.0",
		MaxOriginAmount: "200.0",
		FixedFee:        "10.0",
	}
	jsonData, err := json.Marshal(putData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal putData: %w", err)
	}

	req, err := http.NewRequestWithContext(c.GetTestContext(), http.MethodPut, fmt.Sprintf("http://localhost:%d/quotes", c.port), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", header)

	// Send the request to the server.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send PUT request: %w", err)
	}
	return resp, nil
}

// sendPutAckRequest sends a PUT request to the server with the given authorization header.
func (c *ServerSuite) sendPutAckRequest(header string, txID string) (*http.Response, error) {
	// Prepare the PUT request.
	client := &http.Client{}
	putData := model.PutAckRequest{
		TxID:        txID,
		DestChainID: 42161,
	}
	jsonData, err := json.Marshal(putData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal putData: %w", err)
	}

	req, err := http.NewRequestWithContext(c.GetTestContext(), http.MethodPut, fmt.Sprintf("http://localhost:%d/ack", c.port), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", header)

	// Send the request to the server.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send PUT request: %w", err)
	}
	return resp, nil
}

func (c *ServerSuite) TestContracts() {
	// Start the API server in a separate goroutine and wait for it to initialize.
	c.startQuoterAPIServer()

	client, err := apiClient.NewUnauthenticatedClient(c.handler, fmt.Sprintf("http://localhost:%d", c.port))
	c.Require().NoError(err)

	contracts, err := client.GetRFQContracts(c.GetTestContext())
	c.Require().NoError(err)

	c.Require().Len(contracts.Contracts, 2)
}
