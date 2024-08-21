package botmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/ethereum/go-ethereum/common"
	"github.com/slack-io/slacker"
	"github.com/synapsecns/sanguine/ethergo/chaindata"
	"github.com/synapsecns/sanguine/ethergo/client"
	rfqClient "github.com/synapsecns/sanguine/services/rfq/api/client"
	"github.com/synapsecns/sanguine/services/rfq/contracts/fastbridge"
	"github.com/synapsecns/sanguine/services/rfq/relayer/relapi"
)

func (b *Bot) requiresSignoz(definition *slacker.CommandDefinition) *slacker.CommandDefinition {
	if b.signozEnabled {
		return definition
	}
	return &slacker.CommandDefinition{
		Command:     definition.Command,
		Description: fmt.Sprintf("normally this would \"%s\", but signoz is not configured", definition.Description),
		Examples:    definition.Examples,
		Handler: func(ctx *slacker.CommandContext) {
			_, err := ctx.Response().Reply("cannot run command: signoz is not configured")
			if err != nil {
				log.Println(err)
			}
		},
	}
}

func (b *Bot) makeFastBridge(ctx context.Context, req *relapi.GetQuoteRequestResponse) (*fastbridge.FastBridge, error) {
	client, err := rfqClient.NewUnauthenticatedClient(b.handler, b.cfg.RFQApiURL)
	if err != nil {
		return nil, fmt.Errorf("error creating rfq client: %w", err)
	}

	contracts, err := client.GetRFQContracts(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching rfq contracts: %w", err)
	}

	chainClient, err := b.rpcClient.GetChainClient(ctx, int(req.OriginChainID))
	if err != nil {
		return nil, fmt.Errorf("error getting chain client: %w", err)
	}

	contractAddress, ok := contracts.Contracts[req.OriginChainID]
	if !ok {
		return nil, errors.New("contract address not found")
	}

	fastBridgeHandle, err := fastbridge.NewFastBridge(common.HexToAddress(contractAddress), chainClient)
	if err != nil {
		return nil, fmt.Errorf("error creating fast bridge: %w", err)
	}
	return fastBridgeHandle, nil
}

func getTxAge(ctx context.Context, client client.EVM, res *relapi.GetQuoteRequestStatusResponse) string {
	// TODO: add CreatedAt field to GetQuoteRequestStatusResponse so we don't need to make network calls?
	receipt, err := client.TransactionReceipt(ctx, common.HexToHash(res.OriginTxHash))
	if err != nil {
		return "unknown time ago"
	}
	txBlock, err := client.HeaderByHash(ctx, receipt.BlockHash)
	if err != nil {
		return "unknown time ago"
	}

	return humanize.Time(time.Unix(int64(txBlock.Time), 0))
}

func toExplorerSlackLink(ogHash string) string {
	rfqHash := strings.ToUpper(ogHash)
	// cut off 0x
	if strings.HasPrefix(rfqHash, "0x") {
		rfqHash = strings.ToLower(rfqHash[2:])
	}

	return fmt.Sprintf("<https://explorer.synapseprotocol.com/tx/%s|%s>", rfqHash, ogHash)
}

// produce a salck link if the explorer exists.
func toTXSlackLink(txHash string, chainID uint32) string {
	url := chaindata.ToTXLink(int64(chainID), txHash)
	if url == "" {
		return txHash
	}

	// TODO: remove when we can contorl unfurl
	return fmt.Sprintf("<%s|%s>", url, txHash)
}

func stripLinks(input string) string {
	linkRegex := regexp.MustCompile(`<https?://[^|>]+\|([^>]+)>`)
	return linkRegex.ReplaceAllString(input, "$1")
}
