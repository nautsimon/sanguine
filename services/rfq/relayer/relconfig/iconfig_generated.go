// autogenerated file

package relconfig

import (
	"github.com/synapsecns/sanguine/ethergo/signer/config"
)

// IConfig ...
type IConfig interface {
	// GetChains returns the chains config.
	GetChains() map[int]ChainConfig
	// GetOmniRPCURL returns the OmniRPCURL.
	GetOmniRPCURL() string
	// GetRfqAPIURL returns the RFQ API URL.
	GetRfqAPIURL() string
	// GetDatabase returns the database config.
	GetDatabase() DatabaseConfig
	// GetSigner returns the signer config.
	GetSigner() config.SignerConfig
	// GetFeePricer returns the fee pricer config.
	GetFeePricer() FeePricerConfig
	// GetTokenID returns the tokenID for the given chain and address.
	GetTokenID(chain int, addr string) (string, error)
	// GetQuotableTokens returns the quotable tokens for the given token.
	GetQuotableTokens(token string) ([]string, error)
	// GetNativeToken returns the native token for the given chain.
	GetNativeToken(chainID uint32) (string, error)
	// GetTokenDecimals returns the token decimals for the given chain and token.
	GetTokenDecimals(chainID uint32, token string) (uint8, error)
	// GetTokens returns the tokens for the given chain.
	GetTokens(chainID uint32) (map[string]TokenConfig, error)
	// GetTokenName returns the token name for the given chain and address.
	GetTokenName(chain uint32, addr string) (string, error)
}
