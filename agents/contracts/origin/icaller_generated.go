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
	// AllAgents is a free data retrieval call binding the contract method 0x64ecb518.
	//
	// Solidity: function allAgents(uint32 _domain) view returns(address[])
	AllAgents(opts *bind.CallOpts, _domain uint32) ([]common.Address, error)
	// AllDomains is a free data retrieval call binding the contract method 0x6f225878.
	//
	// Solidity: function allDomains() view returns(uint32[] domains_)
	AllDomains(opts *bind.CallOpts) ([]uint32, error)
	// AmountAgents is a free data retrieval call binding the contract method 0x32254098.
	//
	// Solidity: function amountAgents(uint32 _domain) view returns(uint256)
	AmountAgents(opts *bind.CallOpts, _domain uint32) (*big.Int, error)
	// AmountDomains is a free data retrieval call binding the contract method 0x61b0b357.
	//
	// Solidity: function amountDomains() view returns(uint256)
	AmountDomains(opts *bind.CallOpts) (*big.Int, error)
	// GetAgent is a free data retrieval call binding the contract method 0x1d82873b.
	//
	// Solidity: function getAgent(uint32 _domain, uint256 _agentIndex) view returns(address)
	GetAgent(opts *bind.CallOpts, _domain uint32, _agentIndex *big.Int) (common.Address, error)
	// GetDomain is a free data retrieval call binding the contract method 0x1a7a98e2.
	//
	// Solidity: function getDomain(uint256 _domainIndex) view returns(uint32)
	GetDomain(opts *bind.CallOpts, _domainIndex *big.Int) (uint32, error)
	// GetHistoricalRoot is a free data retrieval call binding the contract method 0xf94adcb4.
	//
	// Solidity: function getHistoricalRoot(uint32 _destination, uint32 _nonce) view returns(bytes32, uint256)
	GetHistoricalRoot(opts *bind.CallOpts, _destination uint32, _nonce uint32) ([32]byte, *big.Int, error)
	// IsActiveAgent is a free data retrieval call binding the contract method 0x0958117d.
	//
	// Solidity: function isActiveAgent(uint32 _domain, address _account) view returns(bool)
	IsActiveAgent(opts *bind.CallOpts, _domain uint32, _account common.Address) (bool, error)
	// IsActiveAgent0 is a free data retrieval call binding the contract method 0x65e1e466.
	//
	// Solidity: function isActiveAgent(address _account) view returns(bool)
	IsActiveAgent0(opts *bind.CallOpts, _account common.Address) (bool, error)
	// IsActiveDomain is a free data retrieval call binding the contract method 0x4f5dbc0d.
	//
	// Solidity: function isActiveDomain(uint32 _domain) view returns(bool)
	IsActiveDomain(opts *bind.CallOpts, _domain uint32) (bool, error)
	// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
	//
	// Solidity: function localDomain() view returns(uint32)
	LocalDomain(opts *bind.CallOpts) (uint32, error)
	// Nonce is a free data retrieval call binding the contract method 0x141c4985.
	//
	// Solidity: function nonce(uint32 _destination) view returns(uint32 latestNonce)
	Nonce(opts *bind.CallOpts, _destination uint32) (uint32, error)
	// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
	//
	// Solidity: function owner() view returns(address)
	Owner(opts *bind.CallOpts) (common.Address, error)
	// Root is a free data retrieval call binding the contract method 0xe65b6bd4.
	//
	// Solidity: function root(uint32 _destination) view returns(bytes32)
	Root(opts *bind.CallOpts, _destination uint32) ([32]byte, error)
	// SuggestAttestation is a free data retrieval call binding the contract method 0xdd0f1f74.
	//
	// Solidity: function suggestAttestation(uint32 _destination) view returns(bytes attestationData)
	SuggestAttestation(opts *bind.CallOpts, _destination uint32) ([]byte, error)
	// SuggestAttestations is a free data retrieval call binding the contract method 0x2d55b866.
	//
	// Solidity: function suggestAttestations() view returns(bytes[] attestationDataArray)
	SuggestAttestations(opts *bind.CallOpts) ([][]byte, error)
	// SystemRouter is a free data retrieval call binding the contract method 0x529d1549.
	//
	// Solidity: function systemRouter() view returns(address)
	SystemRouter(opts *bind.CallOpts) (common.Address, error)
	// Version is a free data retrieval call binding the contract method 0x54fd4d50.
	//
	// Solidity: function version() view returns(string versionString)
	Version(opts *bind.CallOpts) (string, error)
}
