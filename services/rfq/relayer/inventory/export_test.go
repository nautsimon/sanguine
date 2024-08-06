package inventory

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/synapsecns/sanguine/services/rfq/relayer/relconfig"
)

// GetRebalance is a wrapper around the internal getRebalance function.
func GetRebalance(cfg relconfig.Config, tokens map[int]map[common.Address]*TokenMetadata, chainID int, token common.Address) (*RebalanceData, error) {
	return getRebalance(nil, cfg, tokens, chainID, token)
}

// GetRebalanceMetadatas is a wrapper around the internal getRebalanceMetadatas function.
func GetRebalanceMetadatas(cfg relconfig.Config, tokens map[int]map[common.Address]*TokenMetadata, tokenName string, methods []relconfig.RebalanceMethod) (originTokenData, destTokenData *TokenMetadata, method relconfig.RebalanceMethod) {
	return getRebalanceMetadatas(cfg, tokens, tokenName, methods)
}
