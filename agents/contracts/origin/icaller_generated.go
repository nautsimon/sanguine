// autogenerated file

package origin

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// IOriginCaller ...
type IOriginCaller interface {
	// MAXMESSAGEBODYBYTES is a free data retrieval call binding the contract method 0x522ae002.
	//
	// Solidity: function MAX_MESSAGE_BODY_BYTES() view returns(uint256)
	MAXMESSAGEBODYBYTES(opts *bind.CallOpts) (*big.Int, error)
	// SYNAPSEDOMAIN is a free data retrieval call binding the contract method 0xbf61e67e.
	//
	// Solidity: function SYNAPSE_DOMAIN() view returns(uint32)
	SYNAPSEDOMAIN(opts *bind.CallOpts) (uint32, error)
	// VERSION is a free data retrieval call binding the contract method 0xffa1ad74.
	//
	// Solidity: function VERSION() view returns(uint8)
	VERSION(opts *bind.CallOpts) (uint8, error)
	// AllGuards is a free data retrieval call binding the contract method 0x9fe03fa2.
	//
	// Solidity: function allGuards() view returns(address[])
	AllGuards(opts *bind.CallOpts) ([]common.Address, error)
	// AllNotaries is a free data retrieval call binding the contract method 0x9817e315.
	//
	// Solidity: function allNotaries() view returns(address[])
	AllNotaries(opts *bind.CallOpts) ([]common.Address, error)
	// GetGuard is a free data retrieval call binding the contract method 0x629ddf69.
	//
	// Solidity: function getGuard(uint256 _index) view returns(address)
	GetGuard(opts *bind.CallOpts, _index *big.Int) (common.Address, error)
	// GetNotary is a free data retrieval call binding the contract method 0xc07dc7f5.
	//
	// Solidity: function getNotary(uint256 _index) view returns(address)
	GetNotary(opts *bind.CallOpts, _index *big.Int) (common.Address, error)
	// GuardsAmount is a free data retrieval call binding the contract method 0x246c2449.
	//
	// Solidity: function guardsAmount() view returns(uint256)
	GuardsAmount(opts *bind.CallOpts) (*big.Int, error)
	// HistoricalRoots is a free data retrieval call binding the contract method 0x7ea97f40.
	//
	// Solidity: function historicalRoots(uint256 ) view returns(bytes32)
	HistoricalRoots(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error)
	// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
	//
	// Solidity: function localDomain() view returns(uint32)
	LocalDomain(opts *bind.CallOpts) (uint32, error)
	// Nonce is a free data retrieval call binding the contract method 0xaffed0e0.
	//
	// Solidity: function nonce() view returns(uint32 latestNonce)
	Nonce(opts *bind.CallOpts) (uint32, error)
	// NotariesAmount is a free data retrieval call binding the contract method 0x8e62e9ef.
	//
	// Solidity: function notariesAmount() view returns(uint256)
	NotariesAmount(opts *bind.CallOpts) (*big.Int, error)
	// NotaryManager is a free data retrieval call binding the contract method 0xf85b597e.
	//
	// Solidity: function notaryManager() view returns(address)
	NotaryManager(opts *bind.CallOpts) (common.Address, error)
	// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
	//
	// Solidity: function owner() view returns(address)
	Owner(opts *bind.CallOpts) (common.Address, error)
	// Root is a free data retrieval call binding the contract method 0xebf0c717.
	//
	// Solidity: function root() view returns(bytes32)
	Root(opts *bind.CallOpts) ([32]byte, error)
	// SuggestAttestation is a free data retrieval call binding the contract method 0x524787d0.
	//
	// Solidity: function suggestAttestation() view returns(uint32 latestNonce, bytes32 latestRoot)
	SuggestAttestation(opts *bind.CallOpts) (struct {
		LatestNonce uint32
		LatestRoot  [32]byte
	}, error)
	// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
	//
	// Solidity: function systemRouter() view returns(address)
	SystemRouter(opts *bind.CallOpts) (common.Address, error)
}
