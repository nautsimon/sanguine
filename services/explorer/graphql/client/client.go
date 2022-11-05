// Code generated by github.com/Yamashou/gqlgenc, DO NOT EDIT.

package client

import (
	"context"
	"net/http"

	"github.com/Yamashou/gqlgenc/client"
	"github.com/synapsecns/sanguine/services/explorer/graphql/server/graph/model"
)

type Client struct {
	Client *client.Client
}

func NewClient(cli *http.Client, baseURL string, options ...client.HTTPRequestOption) *Client {
	return &Client{Client: client.NewClient(cli, baseURL, options...)}
}

type Query struct {
	BridgeTransactions       []*model.BridgeTransaction      "json:\"bridgeTransactions\" graphql:\"bridgeTransactions\""
	LatestBridgeTransactions []*model.BridgeTransaction      "json:\"latestBridgeTransactions\" graphql:\"latestBridgeTransactions\""
	BridgeAmountStatistic    *model.ValueResult              "json:\"bridgeAmountStatistic\" graphql:\"bridgeAmountStatistic\""
	CountByChainID           []*model.TransactionCountResult "json:\"countByChainId\" graphql:\"countByChainId\""
	CountByTokenAddress      []*model.TokenCountResult       "json:\"countByTokenAddress\" graphql:\"countByTokenAddress\""
	AddressRanking           []*model.AddressRanking         "json:\"addressRanking\" graphql:\"addressRanking\""
	HistoricalStatistics     *model.HistoricalResult         "json:\"historicalStatistics\" graphql:\"historicalStatistics\""
}
type GetBridgeTransactions struct {
	Response []*struct {
		FromInfo *struct {
			ChainID        *int     "json:\"chainId\" graphql:\"chainId\""
			Address        *string  "json:\"address\" graphql:\"address\""
			TxnHash        *string  "json:\"txnHash\" graphql:\"txnHash\""
			Value          *string  "json:\"value\" graphql:\"value\""
			FormattedValue *float64 "json:\"formattedValue\" graphql:\"formattedValue\""
			USDValue       *float64 "json:\"USDValue\" graphql:\"USDValue\""
			TokenAddress   *string  "json:\"tokenAddress\" graphql:\"tokenAddress\""
			TokenSymbol    *string  "json:\"tokenSymbol\" graphql:\"tokenSymbol\""
			BlockNumber    *int     "json:\"blockNumber\" graphql:\"blockNumber\""
			Time           *int     "json:\"time\" graphql:\"time\""
		} "json:\"fromInfo\" graphql:\"fromInfo\""
		ToInfo *struct {
			ChainID        *int     "json:\"chainId\" graphql:\"chainId\""
			Address        *string  "json:\"address\" graphql:\"address\""
			TxnHash        *string  "json:\"txnHash\" graphql:\"txnHash\""
			Value          *string  "json:\"value\" graphql:\"value\""
			FormattedValue *float64 "json:\"formattedValue\" graphql:\"formattedValue\""
			USDValue       *float64 "json:\"USDValue\" graphql:\"USDValue\""
			TokenAddress   *string  "json:\"tokenAddress\" graphql:\"tokenAddress\""
			TokenSymbol    *string  "json:\"tokenSymbol\" graphql:\"tokenSymbol\""
			BlockNumber    *int     "json:\"blockNumber\" graphql:\"blockNumber\""
			Time           *int     "json:\"time\" graphql:\"time\""
		} "json:\"toInfo\" graphql:\"toInfo\""
		Kappa       *string "json:\"kappa\" graphql:\"kappa\""
		Pending     *bool   "json:\"pending\" graphql:\"pending\""
		SwapSuccess *bool   "json:\"swapSuccess\" graphql:\"swapSuccess\""
	} "json:\"response\" graphql:\"response\""
}
type GetLatestBridgeTransactions struct {
	Response []*struct {
		FromInfo *struct {
			ChainID        *int     "json:\"chainId\" graphql:\"chainId\""
			Address        *string  "json:\"address\" graphql:\"address\""
			TxnHash        *string  "json:\"txnHash\" graphql:\"txnHash\""
			Value          *string  "json:\"value\" graphql:\"value\""
			FormattedValue *float64 "json:\"formattedValue\" graphql:\"formattedValue\""
			USDValue       *float64 "json:\"USDValue\" graphql:\"USDValue\""
			TokenAddress   *string  "json:\"tokenAddress\" graphql:\"tokenAddress\""
			TokenSymbol    *string  "json:\"tokenSymbol\" graphql:\"tokenSymbol\""
			BlockNumber    *int     "json:\"blockNumber\" graphql:\"blockNumber\""
			Time           *int     "json:\"time\" graphql:\"time\""
		} "json:\"fromInfo\" graphql:\"fromInfo\""
		ToInfo *struct {
			ChainID        *int     "json:\"chainId\" graphql:\"chainId\""
			Address        *string  "json:\"address\" graphql:\"address\""
			TxnHash        *string  "json:\"txnHash\" graphql:\"txnHash\""
			Value          *string  "json:\"value\" graphql:\"value\""
			FormattedValue *float64 "json:\"formattedValue\" graphql:\"formattedValue\""
			USDValue       *float64 "json:\"USDValue\" graphql:\"USDValue\""
			TokenAddress   *string  "json:\"tokenAddress\" graphql:\"tokenAddress\""
			TokenSymbol    *string  "json:\"tokenSymbol\" graphql:\"tokenSymbol\""
			BlockNumber    *int     "json:\"blockNumber\" graphql:\"blockNumber\""
			Time           *int     "json:\"time\" graphql:\"time\""
		} "json:\"toInfo\" graphql:\"toInfo\""
		Kappa       *string "json:\"kappa\" graphql:\"kappa\""
		Pending     *bool   "json:\"pending\" graphql:\"pending\""
		SwapSuccess *bool   "json:\"swapSuccess\" graphql:\"swapSuccess\""
	} "json:\"response\" graphql:\"response\""
}
type GetBridgeAmountStatistic struct {
	Response *struct {
		USDValue *string "json:\"USDValue\" graphql:\"USDValue\""
	} "json:\"response\" graphql:\"response\""
}
type GetCountByChainID struct {
	Response []*struct {
		Count   *int "json:\"count\" graphql:\"count\""
		ChainID *int "json:\"chainId\" graphql:\"chainId\""
	} "json:\"response\" graphql:\"response\""
}
type GetCountByTokenAddress struct {
	Response []*struct {
		ChainID      *int    "json:\"chainId\" graphql:\"chainId\""
		TokenAddress *string "json:\"tokenAddress\" graphql:\"tokenAddress\""
		Count        *int    "json:\"count\" graphql:\"count\""
	} "json:\"response\" graphql:\"response\""
}
type GetAddressRanking struct {
	Response []*struct {
		Address *string "json:\"address\" graphql:\"address\""
		Count   *int    "json:\"count\" graphql:\"count\""
	} "json:\"response\" graphql:\"response\""
}
type GetHistoricalStatistics struct {
	Response *struct {
		Total       *float64 "json:\"total\" graphql:\"total\""
		DateResults []*struct {
			Date  *string  "json:\"date\" graphql:\"date\""
			Total *float64 "json:\"total\" graphql:\"total\""
		} "json:\"dateResults\" graphql:\"dateResults\""
		Type *model.HistoricalResultType "json:\"type\" graphql:\"type\""
	} "json:\"response\" graphql:\"response\""
}

const GetBridgeTransactionsDocument = `query GetBridgeTransactions ($chainId: Int, $address: String, $txHash: String, $kappa: String, $includePending: Boolean!, $page: Int!, $tokenAddress: String) {
	response: bridgeTransactions(chainId: $chainId, address: $address, txnHash: $txHash, kappa: $kappa, includePending: $includePending, page: $page, tokenAddress: $tokenAddress) {
		fromInfo {
			chainId
			address
			txnHash
			value
			formattedValue
			USDValue
			tokenAddress
			tokenSymbol
			blockNumber
			time
		}
		toInfo {
			chainId
			address
			txnHash
			value
			formattedValue
			USDValue
			tokenAddress
			tokenSymbol
			blockNumber
			time
		}
		kappa
		pending
		swapSuccess
	}
}
`

func (c *Client) GetBridgeTransactions(ctx context.Context, chainID *int, address *string, txHash *string, kappa *string, includePending bool, page int, tokenAddress *string, httpRequestOptions ...client.HTTPRequestOption) (*GetBridgeTransactions, error) {
	vars := map[string]interface{}{
		"chainId":        chainID,
		"address":        address,
		"txHash":         txHash,
		"kappa":          kappa,
		"includePending": includePending,
		"page":           page,
		"tokenAddress":   tokenAddress,
	}

	var res GetBridgeTransactions
	if err := c.Client.Post(ctx, "GetBridgeTransactions", GetBridgeTransactionsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLatestBridgeTransactionsDocument = `query GetLatestBridgeTransactions ($includePending: Boolean!, $page: Int!) {
	response: latestBridgeTransactions(includePending: $includePending, page: $page) {
		fromInfo {
			chainId
			address
			txnHash
			value
			formattedValue
			USDValue
			tokenAddress
			tokenSymbol
			blockNumber
			time
		}
		toInfo {
			chainId
			address
			txnHash
			value
			formattedValue
			USDValue
			tokenAddress
			tokenSymbol
			blockNumber
			time
		}
		kappa
		pending
		swapSuccess
	}
}
`

func (c *Client) GetLatestBridgeTransactions(ctx context.Context, includePending bool, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetLatestBridgeTransactions, error) {
	vars := map[string]interface{}{
		"includePending": includePending,
		"page":           page,
	}

	var res GetLatestBridgeTransactions
	if err := c.Client.Post(ctx, "GetLatestBridgeTransactions", GetLatestBridgeTransactionsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetBridgeAmountStatisticDocument = `query GetBridgeAmountStatistic ($type: StatisticType!, $duration: Duration, $chainId: Int, $address: String, $tokenAddress: String) {
	response: bridgeAmountStatistic(type: $type, duration: $duration, chainId: $chainId, address: $address, tokenAddress: $tokenAddress) {
		USDValue
	}
}
`

func (c *Client) GetBridgeAmountStatistic(ctx context.Context, typeArg model.StatisticType, duration *model.Duration, chainID *int, address *string, tokenAddress *string, httpRequestOptions ...client.HTTPRequestOption) (*GetBridgeAmountStatistic, error) {
	vars := map[string]interface{}{
		"type":         typeArg,
		"duration":     duration,
		"chainId":      chainID,
		"address":      address,
		"tokenAddress": tokenAddress,
	}

	var res GetBridgeAmountStatistic
	if err := c.Client.Post(ctx, "GetBridgeAmountStatistic", GetBridgeAmountStatisticDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetCountByChainIDDocument = `query GetCountByChainId ($chainId: Int, $address: String, $direction: Direction, $hours: Int) {
	response: countByChainId(chainId: $chainId, address: $address, direction: $direction, hours: $hours) {
		count
		chainId
	}
}
`

func (c *Client) GetCountByChainID(ctx context.Context, chainID *int, address *string, direction *model.Direction, hours *int, httpRequestOptions ...client.HTTPRequestOption) (*GetCountByChainID, error) {
	vars := map[string]interface{}{
		"chainId":   chainID,
		"address":   address,
		"direction": direction,
		"hours":     hours,
	}

	var res GetCountByChainID
	if err := c.Client.Post(ctx, "GetCountByChainId", GetCountByChainIDDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetCountByTokenAddressDocument = `query GetCountByTokenAddress ($chainId: Int, $address: String, $direction: Direction, $hours: Int) {
	response: countByTokenAddress(chainId: $chainId, address: $address, direction: $direction, hours: $hours) {
		chainId
		tokenAddress
		count
	}
}
`

func (c *Client) GetCountByTokenAddress(ctx context.Context, chainID *int, address *string, direction *model.Direction, hours *int, httpRequestOptions ...client.HTTPRequestOption) (*GetCountByTokenAddress, error) {
	vars := map[string]interface{}{
		"chainId":   chainID,
		"address":   address,
		"direction": direction,
		"hours":     hours,
	}

	var res GetCountByTokenAddress
	if err := c.Client.Post(ctx, "GetCountByTokenAddress", GetCountByTokenAddressDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetAddressRankingDocument = `query GetAddressRanking ($hours: Int) {
	response: addressRanking(hours: $hours) {
		address
		count
	}
}
`

func (c *Client) GetAddressRanking(ctx context.Context, hours *int, httpRequestOptions ...client.HTTPRequestOption) (*GetAddressRanking, error) {
	vars := map[string]interface{}{
		"hours": hours,
	}

	var res GetAddressRanking
	if err := c.Client.Post(ctx, "GetAddressRanking", GetAddressRankingDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetHistoricalStatisticsDocument = `query GetHistoricalStatistics ($chainId: Int, $type: HistoricalResultType, $days: Int) {
	response: historicalStatistics(chainId: $chainId, type: $type, days: $days) {
		total
		dateResults {
			date
			total
		}
		type
	}
}
`

func (c *Client) GetHistoricalStatistics(ctx context.Context, chainID *int, typeArg *model.HistoricalResultType, days *int, httpRequestOptions ...client.HTTPRequestOption) (*GetHistoricalStatistics, error) {
	vars := map[string]interface{}{
		"chainId": chainID,
		"type":    typeArg,
		"days":    days,
	}

	var res GetHistoricalStatistics
	if err := c.Client.Post(ctx, "GetHistoricalStatistics", GetHistoricalStatisticsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}
