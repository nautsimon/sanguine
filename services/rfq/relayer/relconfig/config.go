// Package relconfig contains the config yaml object for the relayer.
package relconfig

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jftuga/ellipsis"
	"github.com/synapsecns/sanguine/ethergo/signer/config"
	submitterConfig "github.com/synapsecns/sanguine/ethergo/submitter/config"
	cctpConfig "github.com/synapsecns/sanguine/services/cctp-relayer/config"
	"gopkg.in/yaml.v2"

	"path/filepath"
)

// Config represents the configuration for the relayer.
type Config struct {
	// Chains is a map of chainID -> chain config.
	Chains map[int]ChainConfig `yaml:"chains"`
	// BaseChainConfig applies to all chains except those values that are overridden in Chains.
	BaseChainConfig ChainConfig `yaml:"base_chain_config"`
	// OmniRPCURL is the URL of the OmniRPC server.
	OmniRPCURL string `yaml:"omnirpc_url"`
	// RfqAPIURL is the URL of the RFQ API.
	RfqAPIURL string `yaml:"rfq_url"`
	// RelayerAPIPort is the port of the relayer API.
	RelayerAPIPort string `yaml:"relayer_api_port"`
	// Database is the database config.
	Database DatabaseConfig `yaml:"database"`
	// QuotableTokens is a map of token -> list of quotable tokens.
	QuotableTokens map[string][]string `yaml:"quotable_tokens"`
	// Signer is the signer config.
	Signer config.SignerConfig `yaml:"signer"`
	// SubmitterConfig is the submitter config.
	SubmitterConfig submitterConfig.Config `yaml:"submitter_config"`
	// FeePricer is the fee pricer config.
	FeePricer FeePricerConfig `yaml:"fee_pricer"`
	// ScreenerAPIUrl is the TRM API url.
	ScreenerAPIUrl string `yaml:"screener_api_url"`
	// DBSelectorInterval is the interval for the db selector.
	DBSelectorInterval time.Duration `yaml:"db_selector_interval"`
	// RebalanceInterval is the interval for rebalancing.
	RebalanceInterval time.Duration `yaml:"rebalance_interval"`
	// QuoteSubmissionTimeout is the timeout for submitting a quote.
	QuoteSubmissionTimeout time.Duration `yaml:"quote_submission_timeout"`
	// CCTPRelayerConfig is the embedded cctp relayer config (optional).
	CCTPRelayerConfig *cctpConfig.Config `yaml:"cctp_relayer_config"`
	// EnableAPIWithdrawals enables withdrawals via the API.
	EnableAPIWithdrawals bool `yaml:"enable_api_withdrawals"`
	// WithdrawalWhitelist is a list of addresses that are allowed to withdraw.
	WithdrawalWhitelist []string `yaml:"withdrawal_whitelist"`
	// UseEmbeddedGuard enables the embedded guard.
	UseEmbeddedGuard bool `yaml:"enable_guard"`
	// SubmitSingleQuotes enables submitting single quotes.
	SubmitSingleQuotes bool `yaml:"submit_single_quotes"`
}

// ChainConfig represents the configuration for a chain.
type ChainConfig struct {
	// Bridge is the rfq bridge contract address.
	RFQAddress string `yaml:"rfq_address"`
	// SynapseCCTPAddress is the SynapseCCTP address.
	SynapseCCTPAddress string `yaml:"synapse_cctp_address"`
	// TokenMessengerAddress is the TokenMessenger address.
	TokenMessengerAddress string `yaml:"token_messenger_address"`
	// L1GatewayAddress is the L1Gateway address [scroll].
	L1GatewayAddress string `yaml:"l1_gateway_address"`
	// L1ScrollMessengerAddress is the L1ScrollMessenger address [scroll].
	L1ScrollMessengerAddress string `yaml:"l1_scroll_messenger_address"`
	// L2GatewayAddress is the L2Gateway address [scroll].
	L2GatewayAddress string `yaml:"l2_gateway_address"`
	// Confirmations is the number of required confirmations.
	Confirmations uint64 `yaml:"confirmations"`
	// Tokens is a map of token name -> token config.
	Tokens map[string]TokenConfig `yaml:"tokens"`
	// NativeToken is the native token of the chain (pays gas).
	NativeToken string `yaml:"native_token"`
	// DeadlineBufferSeconds is the deadline buffer for relaying a transaction.
	DeadlineBufferSeconds int `yaml:"deadline_buffer_seconds"`
	// OriginGasEstimate is the gas estimate to use for origin transactions (this will override base gas estimates).
	OriginGasEstimate int `yaml:"origin_gas_estimate"`
	// DestGasEstimate is the gas estimate to use for destination transactions (this will override base gas estimates).
	DestGasEstimate int `yaml:"dest_gas_estimate"`
	// L1FeeChainID indicates the chain ID for the L1 fee (if needed, for example on optimism).
	L1FeeChainID uint32 `yaml:"l1_fee_chain_id"`
	// L1FeeOriginGasEstimate is the gas estimate for the L1 fee on origin.
	L1FeeOriginGasEstimate int `yaml:"l1_fee_origin_gas_estimate"`
	// L1FeeDestGasEstimate is the gas estimate for the L1 fee on destination.
	L1FeeDestGasEstimate int `yaml:"l1_fee_dest_gas_estimate"`
	// MinGasToken is minimum amount of gas that should be leftover after bridging a gas token.
	MinGasToken string `yaml:"min_gas_token"`
	// QuotePct is the percent of balance to quote.
	QuotePct float64 `yaml:"quote_pct"`
	// QuoteWidthBps is the number of basis points to deduct from the dest amount.
	// Note that this parameter is applied on a chain level and must be positive.
	QuoteWidthBps float64 `yaml:"quote_width_bps"`
	// QuoteFixedFeeMultiplier is the multiplier for the fixed fee, applied when generating quotes.
	QuoteFixedFeeMultiplier float64 `yaml:"quote_fixed_fee_multiplier"`
	// RelayFixedFeeMultiplier is the multiplier for the fixed fee, applied when relaying.
	RelayFixedFeeMultiplier float64 `yaml:"relay_fixed_fee_multiplier"`
	// CCTP start block is the block at which the chain listener will listen for CCTP events.
	CCTPStartBlock uint64 `yaml:"cctp_start_block"`
}

// TokenConfig represents the configuration for a token.
type TokenConfig struct {
	// Address is the token address.
	Address string `yaml:"address"`
	// Decimals is the token decimals.
	Decimals uint8 `yaml:"decimals"`
	// For now, specify the USD price of the token in the config.
	PriceUSD float64 `yaml:"price_usd"`
	// MinQuoteAmount is the minimum amount to quote for this token in human-readable units.
	MinQuoteAmount string `yaml:"min_quote_amount"`
	// RebalanceMethods are the supported methods for rebalancing.
	RebalanceMethods []string `yaml:"rebalance_methods"`
	// MaintenanceBalancePct is the percentage of the total balance under which a rebalance will be triggered.
	MaintenanceBalancePct float64 `yaml:"maintenance_balance_pct"`
	// InitialBalancePct is the percentage of the total balance to retain when triggering a rebalance.
	InitialBalancePct float64 `yaml:"initial_balance_pct"`
	// MinRebalanceAmount is the minimum amount to rebalance in human-readable units.
	// For USDC-through-cctp pairs this defaults to $1,000.
	MinRebalanceAmount string `yaml:"min_rebalance_amount"`
	// MaxRebalanceAmount is the maximum amount to rebalance in human-readable units.
	MaxRebalanceAmount string `yaml:"max_rebalance_amount"`
	// QuoteOffsetBps is the number of basis points to deduct from the dest amount,
	// and add to the origin amount for a given token,
	// Note that this value can be positive or negative; if positive it effectively increases the quoted price
	// of the given token, and vice versa.
	QuoteOffsetBps float64 `yaml:"quote_offset_bps"`
}

// DatabaseConfig represents the configuration for the database.
type DatabaseConfig struct {
	Type string `yaml:"type"`
	DSN  string `yaml:"dsn"` // Data Source Name
}

// FeePricerConfig represents the configuration for the fee pricer.
type FeePricerConfig struct {
	// GasPriceCacheTTLSeconds is the TTL for the gas price cache.
	GasPriceCacheTTLSeconds int `yaml:"gas_price_cache_ttl"`
	// TokenPriceCacheTTLSeconds is the TTL for the token price cache.
	TokenPriceCacheTTLSeconds int `yaml:"token_price_cache_ttl"`
	// HTTPTimeoutMs is the number of milliseconds to timeout on a HTTP request.
	HTTPTimeoutMs int `yaml:"http_timeout_ms"`
}

// TokenIDDelimiter is the delimiter for token IDs.
const TokenIDDelimiter = "-"

// SanitizeTokenID takes a raw string, makes sure it is a valid token ID,
// and returns the token ID as string with a checksummed address.
func SanitizeTokenID(id string) (sanitized string, err error) {
	split := strings.Split(id, TokenIDDelimiter)
	if len(split) != 2 {
		return sanitized, fmt.Errorf("invalid token ID: %s", id)
	}
	chainID, err := strconv.Atoi(split[0])
	if err != nil {
		return sanitized, fmt.Errorf("invalid chain ID: %s", split[0])
	}
	addr := common.HexToAddress(split[1])
	sanitized = fmt.Sprintf("%d%s%s", chainID, TokenIDDelimiter, addr.Hex())
	return sanitized, nil
}

// DecodeTokenID decodes a token ID into a chain ID and address.
func DecodeTokenID(id string) (chainID int, addr common.Address, err error) {
	// defensive coding, first check if the token ID is valid
	_, err = SanitizeTokenID(id)
	if err != nil {
		return chainID, addr, err
	}

	split := strings.Split(id, TokenIDDelimiter)
	if len(split) != 2 {
		return chainID, addr, fmt.Errorf("invalid token ID: %s", id)
	}
	chainID, err = strconv.Atoi(split[0])
	if err != nil {
		return chainID, addr, fmt.Errorf("invalid chain ID: %s", split[0])
	}
	if !common.IsHexAddress(split[1]) {
		return chainID, addr, fmt.Errorf("invalid address: %s", split[1])
	}

	addr = common.HexToAddress(split[1])
	return chainID, addr, nil
}

// LoadConfig loads the config from the given path.
func LoadConfig(path string) (config Config, err error) {
	input, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Config{}, fmt.Errorf("failed to read file: %w", err)
	}
	err = yaml.Unmarshal(input, &config)
	if err != nil {
		return Config{}, fmt.Errorf("could not unmarshall config %s: %w", ellipsis.Shorten(string(input), 30), err)
	}
	err = config.Validate()
	if err != nil {
		return config, fmt.Errorf("error validating config: %w", err)
	}
	return config, nil
}

// Validate validates the config.
func (c Config) Validate() (err error) {
	maintenancePctSums := map[string]float64{}
	initialPctSums := map[string]float64{}
	for _, chainCfg := range c.Chains {
		for tokenName, tokenCfg := range chainCfg.Tokens {
			if tokenCfg.RebalanceMethod != "" {
				maintenancePctSums[tokenName] += tokenCfg.MaintenanceBalancePct
				initialPctSums[tokenName] += tokenCfg.InitialBalancePct
			}
		}
	}
	for token, sum := range maintenancePctSums {
		if sum > 100 {
			return fmt.Errorf("total maintenance percent exceeds 100 for %s: %f", token, sum)
		}
	}
	for token, sum := range initialPctSums {
		if math.Round(sum) != 100 {
			return fmt.Errorf("total initial percent does not total 100 for %s: %f", token, sum)
		}
	}
	return nil
}
