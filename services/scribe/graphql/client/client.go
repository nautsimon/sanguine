// Code generated by github.com/Yamashou/gqlgenc, DO NOT EDIT.

package client

import (
	"context"
	"net/http"

	"github.com/Yamashou/gqlgenc/client"
	"github.com/synapsecns/sanguine/services/scribe/graphql/server/graph/model"
)

type Client struct {
	Client *client.Client
}

func NewClient(cli *http.Client, baseURL string, options ...client.HTTPRequestOption) *Client {
	return &Client{Client: client.NewClient(cli, baseURL, options...)}
}

type Query struct {
	Logs                     []*model.Log         "json:\"logs\" graphql:\"logs\""
	LogsRange                []*model.Log         "json:\"logsRange\" graphql:\"logsRange\""
	Receipts                 []*model.Receipt     "json:\"receipts\" graphql:\"receipts\""
	ReceiptsRange            []*model.Receipt     "json:\"receiptsRange\" graphql:\"receiptsRange\""
	Transactions             []*model.Transaction "json:\"transactions\" graphql:\"transactions\""
	TransactionsRange        []*model.Transaction "json:\"transactionsRange\" graphql:\"transactionsRange\""
	BlockTime                *int                 "json:\"blockTime\" graphql:\"blockTime\""
	LastStoredBlockNumber    *int                 "json:\"lastStoredBlockNumber\" graphql:\"lastStoredBlockNumber\""
	FirstStoredBlockNumber   *int                 "json:\"firstStoredBlockNumber\" graphql:\"firstStoredBlockNumber\""
	LastConfirmedBlockNumber *int                 "json:\"lastConfirmedBlockNumber\" graphql:\"lastConfirmedBlockNumber\""
	TxSender                 *string              "json:\"txSender\" graphql:\"txSender\""
	LastIndexed              *int                 "json:\"lastIndexed\" graphql:\"lastIndexed\""
	LogCount                 *int                 "json:\"logCount\" graphql:\"logCount\""
	ReceiptCount             *int                 "json:\"receiptCount\" graphql:\"receiptCount\""
	BlockTimeCount           *int                 "json:\"blockTimeCount\" graphql:\"blockTimeCount\""
}
type GetLogs struct {
	Response []*struct {
		ContractAddress string   "json:\"contract_address\" graphql:\"contract_address\""
		ChainID         int      "json:\"chain_id\" graphql:\"chain_id\""
		Topics          []string "json:\"topics\" graphql:\"topics\""
		Data            string   "json:\"data\" graphql:\"data\""
		BlockNumber     int      "json:\"block_number\" graphql:\"block_number\""
		TxHash          string   "json:\"tx_hash\" graphql:\"tx_hash\""
		TxIndex         int      "json:\"tx_index\" graphql:\"tx_index\""
		BlockHash       string   "json:\"block_hash\" graphql:\"block_hash\""
		Index           int      "json:\"index\" graphql:\"index\""
		Removed         bool     "json:\"removed\" graphql:\"removed\""
	} "json:\"response\" graphql:\"response\""
}
type GetLogsRange struct {
	Response []*struct {
		ContractAddress string   "json:\"contract_address\" graphql:\"contract_address\""
		ChainID         int      "json:\"chain_id\" graphql:\"chain_id\""
		Topics          []string "json:\"topics\" graphql:\"topics\""
		Data            string   "json:\"data\" graphql:\"data\""
		BlockNumber     int      "json:\"block_number\" graphql:\"block_number\""
		TxHash          string   "json:\"tx_hash\" graphql:\"tx_hash\""
		TxIndex         int      "json:\"tx_index\" graphql:\"tx_index\""
		BlockHash       string   "json:\"block_hash\" graphql:\"block_hash\""
		Index           int      "json:\"index\" graphql:\"index\""
		Removed         bool     "json:\"removed\" graphql:\"removed\""
	} "json:\"response\" graphql:\"response\""
}
type GetLogsResolvers struct {
	Response []*struct {
		Receipt struct {
			ChainID           int    "json:\"chain_id\" graphql:\"chain_id\""
			Type              int    "json:\"type\" graphql:\"type\""
			PostState         string "json:\"post_state\" graphql:\"post_state\""
			Status            int    "json:\"status\" graphql:\"status\""
			CumulativeGasUsed int    "json:\"cumulative_gas_used\" graphql:\"cumulative_gas_used\""
			Bloom             string "json:\"bloom\" graphql:\"bloom\""
			TxHash            string "json:\"tx_hash\" graphql:\"tx_hash\""
			ContractAddress   string "json:\"contract_address\" graphql:\"contract_address\""
			GasUsed           int    "json:\"gas_used\" graphql:\"gas_used\""
			BlockNumber       int    "json:\"block_number\" graphql:\"block_number\""
			TransactionIndex  int    "json:\"transaction_index\" graphql:\"transaction_index\""
		} "json:\"receipt\" graphql:\"receipt\""
		Transaction struct {
			ChainID   int    "json:\"chain_id\" graphql:\"chain_id\""
			TxHash    string "json:\"tx_hash\" graphql:\"tx_hash\""
			Protected bool   "json:\"protected\" graphql:\"protected\""
			Type      int    "json:\"type\" graphql:\"type\""
			Data      string "json:\"data\" graphql:\"data\""
			Gas       int    "json:\"gas\" graphql:\"gas\""
			GasPrice  int    "json:\"gas_price\" graphql:\"gas_price\""
			GasTipCap string "json:\"gas_tip_cap\" graphql:\"gas_tip_cap\""
			GasFeeCap string "json:\"gas_fee_cap\" graphql:\"gas_fee_cap\""
			Value     string "json:\"value\" graphql:\"value\""
			Nonce     int    "json:\"nonce\" graphql:\"nonce\""
			To        string "json:\"to\" graphql:\"to\""
		} "json:\"transaction\" graphql:\"transaction\""
	} "json:\"response\" graphql:\"response\""
}
type GetReceipts struct {
	Response []*struct {
		ChainID           int    "json:\"chain_id\" graphql:\"chain_id\""
		Type              int    "json:\"type\" graphql:\"type\""
		PostState         string "json:\"post_state\" graphql:\"post_state\""
		Status            int    "json:\"status\" graphql:\"status\""
		CumulativeGasUsed int    "json:\"cumulative_gas_used\" graphql:\"cumulative_gas_used\""
		Bloom             string "json:\"bloom\" graphql:\"bloom\""
		TxHash            string "json:\"tx_hash\" graphql:\"tx_hash\""
		ContractAddress   string "json:\"contract_address\" graphql:\"contract_address\""
		GasUsed           int    "json:\"gas_used\" graphql:\"gas_used\""
		BlockNumber       int    "json:\"block_number\" graphql:\"block_number\""
		TransactionIndex  int    "json:\"transaction_index\" graphql:\"transaction_index\""
	} "json:\"response\" graphql:\"response\""
}
type GetReceiptsRange struct {
	Response []*struct {
		ChainID           int    "json:\"chain_id\" graphql:\"chain_id\""
		Type              int    "json:\"type\" graphql:\"type\""
		PostState         string "json:\"post_state\" graphql:\"post_state\""
		Status            int    "json:\"status\" graphql:\"status\""
		CumulativeGasUsed int    "json:\"cumulative_gas_used\" graphql:\"cumulative_gas_used\""
		Bloom             string "json:\"bloom\" graphql:\"bloom\""
		TxHash            string "json:\"tx_hash\" graphql:\"tx_hash\""
		ContractAddress   string "json:\"contract_address\" graphql:\"contract_address\""
		GasUsed           int    "json:\"gas_used\" graphql:\"gas_used\""
		BlockNumber       int    "json:\"block_number\" graphql:\"block_number\""
		TransactionIndex  int    "json:\"transaction_index\" graphql:\"transaction_index\""
	} "json:\"response\" graphql:\"response\""
}
type GetReceiptsResolvers struct {
	Response []*struct {
		Logs []*struct {
			ContractAddress string   "json:\"contract_address\" graphql:\"contract_address\""
			ChainID         int      "json:\"chain_id\" graphql:\"chain_id\""
			Topics          []string "json:\"topics\" graphql:\"topics\""
			Data            string   "json:\"data\" graphql:\"data\""
			BlockNumber     int      "json:\"block_number\" graphql:\"block_number\""
			TxHash          string   "json:\"tx_hash\" graphql:\"tx_hash\""
			TxIndex         int      "json:\"tx_index\" graphql:\"tx_index\""
			BlockHash       string   "json:\"block_hash\" graphql:\"block_hash\""
			Index           int      "json:\"index\" graphql:\"index\""
			Removed         bool     "json:\"removed\" graphql:\"removed\""
		} "json:\"logs\" graphql:\"logs\""
		Transaction struct {
			ChainID   int    "json:\"chain_id\" graphql:\"chain_id\""
			TxHash    string "json:\"tx_hash\" graphql:\"tx_hash\""
			Protected bool   "json:\"protected\" graphql:\"protected\""
			Type      int    "json:\"type\" graphql:\"type\""
			Data      string "json:\"data\" graphql:\"data\""
			Gas       int    "json:\"gas\" graphql:\"gas\""
			GasPrice  int    "json:\"gas_price\" graphql:\"gas_price\""
			GasTipCap string "json:\"gas_tip_cap\" graphql:\"gas_tip_cap\""
			GasFeeCap string "json:\"gas_fee_cap\" graphql:\"gas_fee_cap\""
			Value     string "json:\"value\" graphql:\"value\""
			Nonce     int    "json:\"nonce\" graphql:\"nonce\""
			To        string "json:\"to\" graphql:\"to\""
		} "json:\"transaction\" graphql:\"transaction\""
	} "json:\"response\" graphql:\"response\""
}
type GetTransactions struct {
	Response []*struct {
		ChainID   int    "json:\"chain_id\" graphql:\"chain_id\""
		TxHash    string "json:\"tx_hash\" graphql:\"tx_hash\""
		Protected bool   "json:\"protected\" graphql:\"protected\""
		Type      int    "json:\"type\" graphql:\"type\""
		Data      string "json:\"data\" graphql:\"data\""
		Gas       int    "json:\"gas\" graphql:\"gas\""
		GasPrice  int    "json:\"gas_price\" graphql:\"gas_price\""
		GasTipCap string "json:\"gas_tip_cap\" graphql:\"gas_tip_cap\""
		GasFeeCap string "json:\"gas_fee_cap\" graphql:\"gas_fee_cap\""
		Value     string "json:\"value\" graphql:\"value\""
		Nonce     int    "json:\"nonce\" graphql:\"nonce\""
		To        string "json:\"to\" graphql:\"to\""
		Timestamp int    "json:\"timestamp\" graphql:\"timestamp\""
		Sender    string "json:\"sender\" graphql:\"sender\""
	} "json:\"response\" graphql:\"response\""
}
type GetTransactionsRange struct {
	Response []*struct {
		ChainID   int    "json:\"chain_id\" graphql:\"chain_id\""
		TxHash    string "json:\"tx_hash\" graphql:\"tx_hash\""
		Protected bool   "json:\"protected\" graphql:\"protected\""
		Type      int    "json:\"type\" graphql:\"type\""
		Data      string "json:\"data\" graphql:\"data\""
		Gas       int    "json:\"gas\" graphql:\"gas\""
		GasPrice  int    "json:\"gas_price\" graphql:\"gas_price\""
		GasTipCap string "json:\"gas_tip_cap\" graphql:\"gas_tip_cap\""
		GasFeeCap string "json:\"gas_fee_cap\" graphql:\"gas_fee_cap\""
		Value     string "json:\"value\" graphql:\"value\""
		Nonce     int    "json:\"nonce\" graphql:\"nonce\""
		To        string "json:\"to\" graphql:\"to\""
		Timestamp int    "json:\"timestamp\" graphql:\"timestamp\""
		Sender    string "json:\"sender\" graphql:\"sender\""
	} "json:\"response\" graphql:\"response\""
}
type GetTransactionsResolvers struct {
	Response []*struct {
		Receipt struct {
			ChainID           int    "json:\"chain_id\" graphql:\"chain_id\""
			Type              int    "json:\"type\" graphql:\"type\""
			PostState         string "json:\"post_state\" graphql:\"post_state\""
			Status            int    "json:\"status\" graphql:\"status\""
			CumulativeGasUsed int    "json:\"cumulative_gas_used\" graphql:\"cumulative_gas_used\""
			Bloom             string "json:\"bloom\" graphql:\"bloom\""
			TxHash            string "json:\"tx_hash\" graphql:\"tx_hash\""
			ContractAddress   string "json:\"contract_address\" graphql:\"contract_address\""
			GasUsed           int    "json:\"gas_used\" graphql:\"gas_used\""
			BlockNumber       int    "json:\"block_number\" graphql:\"block_number\""
			TransactionIndex  int    "json:\"transaction_index\" graphql:\"transaction_index\""
		} "json:\"receipt\" graphql:\"receipt\""
		Logs []*struct {
			ContractAddress string   "json:\"contract_address\" graphql:\"contract_address\""
			ChainID         int      "json:\"chain_id\" graphql:\"chain_id\""
			Topics          []string "json:\"topics\" graphql:\"topics\""
			Data            string   "json:\"data\" graphql:\"data\""
			BlockNumber     int      "json:\"block_number\" graphql:\"block_number\""
			TxHash          string   "json:\"tx_hash\" graphql:\"tx_hash\""
			TxIndex         int      "json:\"tx_index\" graphql:\"tx_index\""
			BlockHash       string   "json:\"block_hash\" graphql:\"block_hash\""
			Index           int      "json:\"index\" graphql:\"index\""
			Removed         bool     "json:\"removed\" graphql:\"removed\""
		} "json:\"logs\" graphql:\"logs\""
	} "json:\"response\" graphql:\"response\""
}
type GetBlockTime struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetLastStoredBlockNumber struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetFirstStoredBlockNumber struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetTxSender struct {
	Response *string "json:\"response\" graphql:\"response\""
}
type GetLastIndexed struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetLastConfirmedBlockNumber struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetLogCount struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetReceiptCount struct {
	Response *int "json:\"response\" graphql:\"response\""
}
type GetBlockTimeCount struct {
	Response *int "json:\"response\" graphql:\"response\""
}

const GetLogsDocument = `query GetLogs ($chain_id: Int!, $page: Int!) {
	response: logs(chain_id: $chain_id, page: $page) {
		contract_address
		chain_id
		topics
		data
		block_number
		tx_hash
		tx_index
		block_hash
		index
		removed
	}
}
`

func (c *Client) GetLogs(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetLogs, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetLogs
	if err := c.Client.Post(ctx, "GetLogs", GetLogsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLogsRangeDocument = `query GetLogsRange ($chain_id: Int!, $start_block: Int!, $end_block: Int!, $page: Int!) {
	response: logsRange(chain_id: $chain_id, start_block: $start_block, end_block: $end_block, page: $page) {
		contract_address
		chain_id
		topics
		data
		block_number
		tx_hash
		tx_index
		block_hash
		index
		removed
	}
}
`

func (c *Client) GetLogsRange(ctx context.Context, chainID int, startBlock int, endBlock int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetLogsRange, error) {
	vars := map[string]interface{}{
		"chain_id":    chainID,
		"start_block": startBlock,
		"end_block":   endBlock,
		"page":        page,
	}

	var res GetLogsRange
	if err := c.Client.Post(ctx, "GetLogsRange", GetLogsRangeDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLogsResolversDocument = `query GetLogsResolvers ($chain_id: Int!, $page: Int!) {
	response: logs(chain_id: $chain_id, page: $page) {
		receipt {
			chain_id
			type
			post_state
			status
			cumulative_gas_used
			bloom
			tx_hash
			contract_address
			gas_used
			block_number
			transaction_index
		}
		transaction {
			chain_id
			tx_hash
			protected
			type
			data
			gas
			gas_price
			gas_tip_cap
			gas_fee_cap
			value
			nonce
			to
		}
	}
}
`

func (c *Client) GetLogsResolvers(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetLogsResolvers, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetLogsResolvers
	if err := c.Client.Post(ctx, "GetLogsResolvers", GetLogsResolversDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetReceiptsDocument = `query GetReceipts ($chain_id: Int!, $page: Int!) {
	response: receipts(chain_id: $chain_id, page: $page) {
		chain_id
		type
		post_state
		status
		cumulative_gas_used
		bloom
		tx_hash
		contract_address
		gas_used
		block_number
		transaction_index
	}
}
`

func (c *Client) GetReceipts(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetReceipts, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetReceipts
	if err := c.Client.Post(ctx, "GetReceipts", GetReceiptsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetReceiptsRangeDocument = `query GetReceiptsRange ($chain_id: Int!, $start_block: Int!, $end_block: Int!, $page: Int!) {
	response: receiptsRange(chain_id: $chain_id, start_block: $start_block, end_block: $end_block, page: $page) {
		chain_id
		type
		post_state
		status
		cumulative_gas_used
		bloom
		tx_hash
		contract_address
		gas_used
		block_number
		transaction_index
	}
}
`

func (c *Client) GetReceiptsRange(ctx context.Context, chainID int, startBlock int, endBlock int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetReceiptsRange, error) {
	vars := map[string]interface{}{
		"chain_id":    chainID,
		"start_block": startBlock,
		"end_block":   endBlock,
		"page":        page,
	}

	var res GetReceiptsRange
	if err := c.Client.Post(ctx, "GetReceiptsRange", GetReceiptsRangeDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetReceiptsResolversDocument = `query GetReceiptsResolvers ($chain_id: Int!, $page: Int!) {
	response: receipts(chain_id: $chain_id, page: $page) {
		logs {
			contract_address
			chain_id
			topics
			data
			block_number
			tx_hash
			tx_index
			block_hash
			index
			removed
		}
		transaction {
			chain_id
			tx_hash
			protected
			type
			data
			gas
			gas_price
			gas_tip_cap
			gas_fee_cap
			value
			nonce
			to
		}
	}
}
`

func (c *Client) GetReceiptsResolvers(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetReceiptsResolvers, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetReceiptsResolvers
	if err := c.Client.Post(ctx, "GetReceiptsResolvers", GetReceiptsResolversDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetTransactionsDocument = `query GetTransactions ($chain_id: Int!, $page: Int!) {
	response: transactions(chain_id: $chain_id, page: $page) {
		chain_id
		tx_hash
		protected
		type
		data
		gas
		gas_price
		gas_tip_cap
		gas_fee_cap
		value
		nonce
		to
		timestamp
		sender
	}
}
`

func (c *Client) GetTransactions(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetTransactions, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetTransactions
	if err := c.Client.Post(ctx, "GetTransactions", GetTransactionsDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetTransactionsRangeDocument = `query GetTransactionsRange ($chain_id: Int!, $start_block: Int!, $end_block: Int!, $page: Int!) {
	response: transactionsRange(chain_id: $chain_id, start_block: $start_block, end_block: $end_block, page: $page) {
		chain_id
		tx_hash
		protected
		type
		data
		gas
		gas_price
		gas_tip_cap
		gas_fee_cap
		value
		nonce
		to
		timestamp
		sender
	}
}
`

func (c *Client) GetTransactionsRange(ctx context.Context, chainID int, startBlock int, endBlock int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetTransactionsRange, error) {
	vars := map[string]interface{}{
		"chain_id":    chainID,
		"start_block": startBlock,
		"end_block":   endBlock,
		"page":        page,
	}

	var res GetTransactionsRange
	if err := c.Client.Post(ctx, "GetTransactionsRange", GetTransactionsRangeDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetTransactionsResolversDocument = `query GetTransactionsResolvers ($chain_id: Int!, $page: Int!) {
	response: transactions(chain_id: $chain_id, page: $page) {
		receipt {
			chain_id
			type
			post_state
			status
			cumulative_gas_used
			bloom
			tx_hash
			contract_address
			gas_used
			block_number
			transaction_index
		}
		logs {
			contract_address
			chain_id
			topics
			data
			block_number
			tx_hash
			tx_index
			block_hash
			index
			removed
		}
	}
}
`

func (c *Client) GetTransactionsResolvers(ctx context.Context, chainID int, page int, httpRequestOptions ...client.HTTPRequestOption) (*GetTransactionsResolvers, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"page":     page,
	}

	var res GetTransactionsResolvers
	if err := c.Client.Post(ctx, "GetTransactionsResolvers", GetTransactionsResolversDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetBlockTimeDocument = `query GetBlockTime ($chain_id: Int!, $block_number: Int!) {
	response: blockTime(chain_id: $chain_id, block_number: $block_number)
}
`

func (c *Client) GetBlockTime(ctx context.Context, chainID int, blockNumber int, httpRequestOptions ...client.HTTPRequestOption) (*GetBlockTime, error) {
	vars := map[string]interface{}{
		"chain_id":     chainID,
		"block_number": blockNumber,
	}

	var res GetBlockTime
	if err := c.Client.Post(ctx, "GetBlockTime", GetBlockTimeDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLastStoredBlockNumberDocument = `query GetLastStoredBlockNumber ($chain_id: Int!) {
	response: lastStoredBlockNumber(chain_id: $chain_id)
}
`

func (c *Client) GetLastStoredBlockNumber(ctx context.Context, chainID int, httpRequestOptions ...client.HTTPRequestOption) (*GetLastStoredBlockNumber, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
	}

	var res GetLastStoredBlockNumber
	if err := c.Client.Post(ctx, "GetLastStoredBlockNumber", GetLastStoredBlockNumberDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetFirstStoredBlockNumberDocument = `query GetFirstStoredBlockNumber ($chain_id: Int!) {
	response: firstStoredBlockNumber(chain_id: $chain_id)
}
`

func (c *Client) GetFirstStoredBlockNumber(ctx context.Context, chainID int, httpRequestOptions ...client.HTTPRequestOption) (*GetFirstStoredBlockNumber, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
	}

	var res GetFirstStoredBlockNumber
	if err := c.Client.Post(ctx, "GetFirstStoredBlockNumber", GetFirstStoredBlockNumberDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetTxSenderDocument = `query GetTxSender ($chain_id: Int!, $tx_hash: String!) {
	response: txSender(chain_id: $chain_id, tx_hash: $tx_hash)
}
`

func (c *Client) GetTxSender(ctx context.Context, chainID int, txHash string, httpRequestOptions ...client.HTTPRequestOption) (*GetTxSender, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
		"tx_hash":  txHash,
	}

	var res GetTxSender
	if err := c.Client.Post(ctx, "GetTxSender", GetTxSenderDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLastIndexedDocument = `query GetLastIndexed ($chain_id: Int!, $contract_address: String!) {
	response: lastIndexed(chain_id: $chain_id, contract_address: $contract_address)
}
`

func (c *Client) GetLastIndexed(ctx context.Context, chainID int, contractAddress string, httpRequestOptions ...client.HTTPRequestOption) (*GetLastIndexed, error) {
	vars := map[string]interface{}{
		"chain_id":         chainID,
		"contract_address": contractAddress,
	}

	var res GetLastIndexed
	if err := c.Client.Post(ctx, "GetLastIndexed", GetLastIndexedDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLastConfirmedBlockNumberDocument = `query GetLastConfirmedBlockNumber ($chain_id: Int!) {
	response: lastConfirmedBlockNumber(chain_id: $chain_id)
}
`

func (c *Client) GetLastConfirmedBlockNumber(ctx context.Context, chainID int, httpRequestOptions ...client.HTTPRequestOption) (*GetLastConfirmedBlockNumber, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
	}

	var res GetLastConfirmedBlockNumber
	if err := c.Client.Post(ctx, "GetLastConfirmedBlockNumber", GetLastConfirmedBlockNumberDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetLogCountDocument = `query GetLogCount ($chain_id: Int!, $contract_address: String!) {
	response: logCount(chain_id: $chain_id, contract_address: $contract_address)
}
`

func (c *Client) GetLogCount(ctx context.Context, chainID int, contractAddress string, httpRequestOptions ...client.HTTPRequestOption) (*GetLogCount, error) {
	vars := map[string]interface{}{
		"chain_id":         chainID,
		"contract_address": contractAddress,
	}

	var res GetLogCount
	if err := c.Client.Post(ctx, "GetLogCount", GetLogCountDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetReceiptCountDocument = `query GetReceiptCount ($chain_id: Int!, $contract_address: String!) {
	response: receiptCount(chain_id: $chain_id, contract_address: $contract_address)
}
`

func (c *Client) GetReceiptCount(ctx context.Context, chainID int, contractAddress string, httpRequestOptions ...client.HTTPRequestOption) (*GetReceiptCount, error) {
	vars := map[string]interface{}{
		"chain_id":         chainID,
		"contract_address": contractAddress,
	}

	var res GetReceiptCount
	if err := c.Client.Post(ctx, "GetReceiptCount", GetReceiptCountDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}

const GetBlockTimeCountDocument = `query GetBlockTimeCount ($chain_id: Int!) {
	response: blockTimeCount(chain_id: $chain_id)
}
`

func (c *Client) GetBlockTimeCount(ctx context.Context, chainID int, httpRequestOptions ...client.HTTPRequestOption) (*GetBlockTimeCount, error) {
	vars := map[string]interface{}{
		"chain_id": chainID,
	}

	var res GetBlockTimeCount
	if err := c.Client.Post(ctx, "GetBlockTimeCount", GetBlockTimeCountDocument, &res, vars, httpRequestOptions...); err != nil {
		return nil, err
	}

	return &res, nil
}
