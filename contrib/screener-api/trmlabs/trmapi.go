package chainalysis

import (
	"context"

	"github.com/go-resty/resty/v2"
)

// Client is the interface for the TRM Labs API client.
type Client interface {
	ScreenAddress(ctx context.Context, address string) ([]Entity, error)
}

// clientImpl is the implementation of the TRM Labs API client.
type clientImpl struct {
	client *resty.Client
	apiKey string
	url    string
}

// NewClient creates a new TRM Labs API client.
func NewClient(apiKey, url string) (Client, error) {
	client := resty.New().
		SetBaseURL(url).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json").
		SetBasicAuth(apiKey, apiKey)

	return &clientImpl{
		client: client,
		apiKey: apiKey,
		url:    url,
	}, nil
}

func (c *clientImpl) ScreenAddress(ctx context.Context, address string) ([]Entity, error) {
	var result []Entity

	_, err := c.client.R().
		SetContext(ctx).
		SetResult(&result).
		Get("/v1/screen/address/" + address)
	if err != nil {
		return []Entity{}, err
	}

	return result, nil

}

func (c *clientImpl) RegisterAddress(ctx context.Context, address string) error {
	_, err := c.client.R().
		SetContext(ctx).
		Get("/api/risk/v2/entities/" + address)
	if err != nil {
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

// // ScreenResponse is the response from the screening endpoint.
// type ScreenResponse struct {
// 	AccountExternalID        string                 `json:"accountExternalId"`
// 	Address                  string                 `json:"address"`
// 	AddressIncomingVolumeUsd string                 `json:"addressIncomingVolumeUsd"`
// 	AddressOutgoingVolumeUsd string                 `json:"addressOutgoingVolumeUsd"`
// 	AddressRiskIndicators    []AddressRiskIndicator `json:"addressRiskIndicators"`
// 	AddressSubmitted         string                 `json:"addressSubmitted"`
// 	AddressTotalVolumeUsd    string                 `json:"addressTotalVolumeUsd"`
// 	Chain                    string                 `json:"chain"`
// 	Entities                 []interface{}          `json:"entities"`
// 	ExternalID               string                 `json:"externalId"`
// 	TrmAppURL                string                 `json:"trmAppUrl"`
// }
//
// // AddressRiskIndicator is a risk indicator for an address.
// type AddressRiskIndicator struct {
// 	Category                    string `json:"category"`
// 	CategoryID                  string `json:"categoryId"`
// 	CategoryRiskScoreLevel      int    `json:"categoryRiskScoreLevel"`
// 	CategoryRiskScoreLevelLabel string `json:"categoryRiskScoreLevelLabel"`
// 	IncomingVolumeUsd           string `json:"incomingVolumeUsd"`
// 	OutgoingVolumeUsd           string `json:"outgoingVolumeUsd"`
// 	RiskType                    string `json:"riskType"`
// 	TotalVolumeUsd              string `json:"totalVolumeUsd"`
// }
//
// type screenRequest struct {
// 	Address           string `json:"address"`
// 	Chain             string `json:"chain"`
// 	AccountExternalID string `json:"accountExternalId"`
// 	ExternalID        string `json:"externalId"`
// }
//
// func (c *clientImpl) ScreenAddress(ctx context.Context, address string) ([]ScreenResponse, error) {
// 	body := []screenRequest{
// 		{
// 			Address:           address,
// 			Chain:             "ethereum",
// 			AccountExternalID: address,
// 			ExternalID:        address,
// 		},
// 	}
//
// 	var result []ScreenResponse
//
// 	_, err := c.client.R().
// 		SetContext(ctx).
// 		SetBody(body).
// 		SetResult(&result).
// 		Post("/public/v2/screening/addresses")
// 	if err != nil {
// 		return []ScreenResponse{}, fmt.Errorf("could not screen address: %w", err)
// 	}
//
// 	return result, nil
// }
