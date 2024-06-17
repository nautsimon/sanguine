package chainalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	// EntityEndpoint is the endpoint for the entity API.
	EntityEndpoint = "/api/risk/v2/entities"
)

// Client is the interface for the Chainalysis API client. It makes requests to the Chainalysis API.
type Client interface {
	ScreenAddress(ctx context.Context, address string) (bool, error)
}

// clientImpl is the implementation of the Chainalysis API client.
type clientImpl struct {
	client *resty.Client
	apiKey string
	url    string
}

// NewClient creates a new Chainalysis API client.
func NewClient(apiKey, url string) (Client, error) {
	client := resty.New().
		SetBaseURL(url).
		SetHeader("Content-Type", "application/json").
		SetHeader("Token", apiKey).
		SetTimeout(30 * time.Second)

	return &clientImpl{
		client: client,
		apiKey: apiKey,
		url:    url,
	}, nil
}

// ScreenAddress screens an address from the Chainalysis API.
func (c *clientImpl) ScreenAddress(ctx context.Context, address string) (bool, error) {
	// Get the response.
	resp, err := c.client.R().
		SetContext(ctx).
		SetPathParam("address", address).
		Get(EntityEndpoint)
	if err != nil {
		return false, err
	}

	return c.handleResponse(ctx, address, resp)
}

// handleResponse takes the Chainalysis response, and depending if the address is registered or not, returns the result.
// It will retry the request if the address is not registered.
func (c clientImpl) handleResponse(ctx context.Context, address string, resp *resty.Response) (bool, error) {
	// Response could differ based on if the address is registered or not.
	var rawResponse map[string]interface{}
	var err error
	if err := json.Unmarshal(resp.Body(), &rawResponse); err != nil {
		return false, fmt.Errorf("could not unmarshal response: %w", err)
	}

	var result Entity
	// User is not registed.
	if _, ok := rawResponse["message"]; ok {
		// So register it.
		if err = c.registerAddress(ctx, address); err != nil {
			return false, fmt.Errorf("could not register address: %w", err)
		}

		// Then try again.
		time.Sleep(1 * time.Second)
		if resp, err = c.client.R().
			SetContext(ctx).
			SetPathParam("address", address).
			Get(EntityEndpoint); err != nil {
			return false, err
		}
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return false, fmt.Errorf("could not unmarshal response: %w", err)
	}
	if result.Risk == "severe" {
		return true, nil
	}

	return false, nil
}

// registerAddress registers an address in the case that we try and screen for a nonexistent address.
func (c *clientImpl) registerAddress(ctx context.Context, address string) error {
	if _, err := c.client.R().
		SetContext(ctx).
		SetPathParams(map[string]string{"address": address}).
		Post(EntityEndpoint); err != nil {
		return err
	}

	return nil
}

type Entity struct {
	Address                string                  `json:"address"`
	Risk                   string                  `json:"risk"`
	RiskReason             string                  `json:"riskReason"`
	Cluster                Cluster                 `json:"cluster"`
	AddressIdentifications []AddressIdentification `json:"addressIdentifications"`
	Exposures              []Exposure              `json:"exposures"`
	Triggers               []Trigger               `json:"triggers"`
	Status                 string                  `json:"status"`
}

type Cluster struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

type AddressIdentification struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type Exposure struct {
	Category string  `json:"category"`
	Value    float64 `json:"value"`
}

type Trigger struct {
	Category      string        `json:"category"`
	Percentage    float64       `json:"percentage"`
	Message       string        `json:"message"`
	RuleTriggered RuleTriggered `json:"ruleTriggered"`
}

type RuleTriggered struct {
	Risk         string  `json:"risk"`
	MinThreshold float64 `json:"minThreshold"`
	MaxThreshold float64 `json:"maxThreshold"`
}

var _ Client = &clientImpl{}
