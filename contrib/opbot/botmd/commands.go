// Package botmd provides the bot server. Here botmd=cmd not markdown.
// nolint: forcetypeassert, mnd, cyclop
package botmd

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hako/durafmt"
	"github.com/slack-go/slack"
	"github.com/slack-io/slacker"
	"github.com/synapsecns/sanguine/contrib/opbot/signoz"
	"github.com/synapsecns/sanguine/core/retry"
	"github.com/synapsecns/sanguine/services/rfq/relayer/relapi"
)

// nolint: traceCommand, gocognit
// TODO: add trace middleware.
func (b *Bot) traceCommand() *slacker.CommandDefinition {
	return b.requiresSignoz(&slacker.CommandDefinition{
		Command:     "trace <tags>",
		Description: "find a transaction in signoz",
		Examples: []string{
			"trace transaction_id:0x1234 serviceName:rfq",
		},
		Handler: func(ctx *slacker.CommandContext) {
			tags := stripLinks(ctx.Request().Param("tags"))
			splitTags := strings.Split(tags, " ")
			if len(splitTags) == 0 {
				_, err := ctx.Response().Reply("please provide tags in a key:value format")
				if err != nil {
					log.Println(err)
				}
				return
			}

			searchMap := make(map[string]string)
			for _, combinedTag := range splitTags {
				tag := strings.Split(combinedTag, ":")
				if len(tag) != 2 {
					_, err := ctx.Response().Reply("please provide tags in a key:value format")
					if err != nil {
						log.Println(err)
					}
					return
				}
				searchMap[tag[0]] = tag[1]
			}

			// search for the transaction
			res, err := b.signozClient.SearchTraces(ctx.Context(), signoz.Last3Hr, searchMap)
			if err != nil {
				_, err := ctx.Response().Reply("error searching for the transaction")
				if err != nil {
					log.Println(err)
				}
				return
			}

			if res.Status != "success" || res.Data.ContextTimeout || len(res.Data.Result) != 1 {
				_, err := ctx.Response().Reply(fmt.Sprintf("error searching for the transaction %s", res.Data.ContextTimeoutMessage))
				if err != nil {
					log.Println(err)
				}
				return
			}

			traceList := res.Data.Result[0].List
			if len(traceList) == 0 {
				_, err := ctx.Response().Reply("no transaction found")
				if err != nil {
					log.Println(err)
				}
				return
			}

			slackBlocks := []slack.Block{slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, fmt.Sprintf("Traces for %s", tags), false, false))}

			for _, results := range traceList {
				trace := results.Data["traceID"].(string)
				spanID := results.Data["spanID"].(string)
				serviceName := results.Data["serviceName"].(string)

				url := fmt.Sprintf("%s/trace/%s?spanId=%s", b.cfg.SignozBaseURL, trace, spanID)
				traceName := fmt.Sprintf("<%s|%s>", url, results.Data["name"].(string))

				relativeTime := durafmt.Parse(time.Since(results.Timestamp)).LimitFirstN(1).String()

				slackBlocks = append(slackBlocks, slack.NewSectionBlock(nil, []*slack.TextBlockObject{
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*Name*: %s", traceName),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*Service*: %s", serviceName),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*When*: %s", fmt.Sprintf("%s ago", relativeTime)),
					},
				}, nil))
			}

			_, err = ctx.Response().ReplyBlocks(slackBlocks, slacker.WithUnfurlLinks(false))
			if err != nil {
				log.Println(err)
			}
		},
	})
}

// nolint: gocognit
func (b *Bot) rfqLookupCommand() *slacker.CommandDefinition {
	return &slacker.CommandDefinition{
		Command:     "rfq <tx>",
		Description: "find a rfq transaction by either tx hash or txid on all configured relayers",
		Examples: []string{
			"rfq 0x30f96b45ba689c809f7e936c140609eb31c99b182bef54fccf49778716a7e1ca",
		},
		Handler: func(ctx *slacker.CommandContext) {
			type Status struct {
				relayer string
				*relapi.GetQuoteRequestStatusResponse
			}

			var statuses []Status
			var sliceMux sync.Mutex

			if len(b.cfg.RelayerURLS) == 0 {
				_, err := ctx.Response().Reply("no relayer urls configured")
				if err != nil {
					log.Println(err)
				}
				return
			}

			tx := stripLinks(ctx.Request().Param("tx"))

			var wg sync.WaitGroup
			// 2 routines per relayer, one for tx hashh one for tx id
			wg.Add(len(b.cfg.RelayerURLS) * 2)
			for _, relayer := range b.cfg.RelayerURLS {
				client := relapi.NewRelayerClient(b.handler, relayer)
				go func() {
					defer wg.Done()
					res, err := client.GetQuoteRequestStatusByTxHash(ctx.Context(), tx)
					if err != nil {
						log.Printf("error fetching quote request status by tx hash: %v\n", err)
						return
					}
					sliceMux.Lock()
					defer sliceMux.Unlock()
					statuses = append(statuses, Status{relayer: relayer, GetQuoteRequestStatusResponse: res})
				}()

				go func() {
					defer wg.Done()
					res, err := client.GetQuoteRequestStatusByTxID(ctx.Context(), tx)
					if err != nil {
						log.Printf("error fetching quote request status by tx id: %v\n", err)
						return
					}
					sliceMux.Lock()
					defer sliceMux.Unlock()
					statuses = append(statuses, Status{relayer: relayer, GetQuoteRequestStatusResponse: res})
				}()
			}
			wg.Wait()

			if len(statuses) == 0 {
				_, err := ctx.Response().Reply("no quote request found")
				if err != nil {
					log.Println(err)
				}
				return
			}

			var slackBlocks []slack.Block

			for _, status := range statuses {
				client, err := b.rpcClient.GetChainClient(ctx.Context(), int(status.OriginChainID))
				if err != nil {
					log.Printf("error getting chain client: %v\n", err)
				}

				objects := []*slack.TextBlockObject{
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*Relayer*: %s", status.relayer),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*Status*: %s", status.Status),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*TxID*: %s", toExplorerSlackLink(status.TxID)),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*OriginTxHash*: %s", toTXSlackLink(status.OriginTxHash, status.OriginChainID)),
					},
					{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*Estimated Tx Age*: %s", getTxAge(ctx.Context(), client, status.GetQuoteRequestStatusResponse)),
					},
				}

				if status.DestTxHash == (common.Hash{}).String() {
					objects = append(objects, &slack.TextBlockObject{
						Type: slack.MarkdownType,
						Text: "*DestTxHash*: not available",
					})
				} else {
					objects = append(objects, &slack.TextBlockObject{
						Type: slack.MarkdownType,
						Text: fmt.Sprintf("*DestTxHash*: %s", toTXSlackLink(status.DestTxHash, status.DestChainID)),
					})
				}

				slackBlocks = append(slackBlocks, slack.NewSectionBlock(nil, objects, nil))
			}

			_, err := ctx.Response().ReplyBlocks(slackBlocks, slacker.WithUnfurlLinks(false))
			if err != nil {
				log.Println(err)
			}
		},
	}
}

// nolint: gocognit, cyclop.
func (b *Bot) rfqRefund() *slacker.CommandDefinition {
	return &slacker.CommandDefinition{
		Command:     "refund <tx>",
		Description: "refund a quote request",
		Examples:    []string{"refund 0x1234"},
		Handler: func(ctx *slacker.CommandContext) {
			tx := stripLinks(ctx.Request().Param("tx"))

			if len(tx) == 0 {
				_, err := ctx.Response().Reply("please provide a tx hash")
				if err != nil {
					log.Println(err)
				}
				return
			}

			var rawRequest *relapi.GetQuoteRequestResponse
			var err error
			var relClient relapi.RelayerClient
			for _, relayer := range b.cfg.RelayerURLS {
				relClient = relapi.NewRelayerClient(b.handler, relayer)

				rawRequest, err = relClient.GetQuoteRequestByTxHash(ctx.Context(), tx)
				if err != nil {
					continue
				}
			}

			fastBridgeContract, err := b.makeFastBridge(ctx.Context(), rawRequest)
			if err != nil {
				_, err := ctx.Response().Reply(err.Error())
				if err != nil {
					log.Println(err)
				}
				return
			}
			nonce, err := b.submitter.SubmitTransaction(ctx.Context(), big.NewInt(int64(rawRequest.OriginChainID)), func(transactor *bind.TransactOpts) (tx *types.Transaction, err error) {
				tx, err = fastBridgeContract.Refund(transactor, common.Hex2Bytes(rawRequest.QuoteRequestRaw))
				if err != nil {
					return nil, fmt.Errorf("error submitting refund: %w", err)
				}
				return tx, nil
			})
			if err != nil {
				log.Printf("error submitting refund: %v\n", err)
				_, err := ctx.Response().Reply(fmt.Sprintf("error submitting refund: %v", err))
				if err != nil {
					log.Println(err)
				}
			}

			// TODO: follow the lead of https://github.com/synapsecns/sanguine/pull/2845
			var txHash *relapi.TxHashByNonceResponse
			err = retry.WithBackoff(
				ctx.Context(),
				func(ctx context.Context) error {
					txHash, err = relClient.GetTxHashByNonce(
						ctx,
						&relapi.GetTxByNonceRequest{
							ChainID: rawRequest.OriginChainID,
							Nonce:   nonce,
						})
					if err != nil {
						return err
					}
					return nil
				},
			)

			_, err = ctx.Response().Reply(
				fmt.Sprintf(
					"refund submitted with nonce %s",
					toTXSlackLink(txHash.Hash, rawRequest.OriginChainID)),
			)
			if err != nil {
				log.Println(err)
			}
			return
		},
	}
}
