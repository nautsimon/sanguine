package chainalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

// Client is the interface for the Chainalysis API client.
type Client interface {
	ScreenAddress(ctx context.Context, address string) (*Entity, error)
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

// ScreenAddress screens an address.
func (c *clientImpl) ScreenAddress(ctx context.Context, address string) (*Entity, error) {
	// Get the response.
	resp, err := c.client.R().
		SetContext(ctx).
		SetBody(map[string]string{"address": address}).
		Get("/api/risk/v2/entities")
	if err != nil {
		return nil, err
	}

	// Response could differ based on if the address is registered or not.
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &rawResponse); err != nil {
		return nil, fmt.Errorf("could not unmarshal response: %w", err)
	}

	var result Entity
	// User is not registed.
	if _, ok := rawResponse["message"]; ok {
		// So register it.
		err = c.RegisterAddress(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("could not register address: %w", err)
		}
		// Then try again.
		resp, err = c.client.R().
			SetContext(ctx).
			SetBody(map[string]string{"address": address}).
			Get("/api/risk/v2/entities")
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(resp.Body(), &result); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	} else {
		if err := json.Unmarshal(resp.Body(), &result); err != nil {
			return nil, fmt.Errorf("could not unmarshal response: %w", err)
		}
	}

	return &result, nil
}

// RegisterAddress registers an address.
func (c *clientImpl) RegisterAddress(ctx context.Context, address string) error {
	if _, err := c.client.R().
		SetContext(ctx).
		SetPathParams(map[string]string{"address": address}).
		Post("/api/risk/v2/entities/{address}"); err != nil {
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
