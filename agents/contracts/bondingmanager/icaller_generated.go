// autogenerated file

package bondingmanager

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

// IBondingManagerCaller ...
type IBondingManagerCaller interface {
	// AgentLeaf is a free data retrieval call binding the contract method 0xc99dcb9e.
	//
	// Solidity: function agentLeaf(address agent) view returns(bytes32 leaf)
	AgentLeaf(opts *bind.CallOpts, agent common.Address) ([32]byte, error)
	// AgentRoot is a free data retrieval call binding the contract method 0x36cba43c.
	//
	// Solidity: function agentRoot() view returns(bytes32)
	AgentRoot(opts *bind.CallOpts) ([32]byte, error)
	// AgentStatus is a free data retrieval call binding the contract method 0x28f3fac9.
	//
	// Solidity: function agentStatus(address agent) view returns((uint8,uint32,uint32) status)
	AgentStatus(opts *bind.CallOpts, agent common.Address) (AgentStatus, error)
	// AllLeafs is a free data retrieval call binding the contract method 0x12db2ef6.
	//
	// Solidity: function allLeafs() view returns(bytes32[] leafs)
	AllLeafs(opts *bind.CallOpts) ([][32]byte, error)
	// Destination is a free data retrieval call binding the contract method 0xb269681d.
	//
	// Solidity: function destination() view returns(address)
	Destination(opts *bind.CallOpts) (common.Address, error)
	// DisputeStatus is a free data retrieval call binding the contract method 0x3463d1b1.
	//
	// Solidity: function disputeStatus(address agent) view returns(uint8 flag, address rival, address fraudProver, uint256 disputePtr)
	DisputeStatus(opts *bind.CallOpts, agent common.Address) (struct {
		Flag        uint8
		Rival       common.Address
		FraudProver common.Address
		DisputePtr  *big.Int
	}, error)
	// GetActiveAgents is a free data retrieval call binding the contract method 0xc1c0f4f6.
	//
	// Solidity: function getActiveAgents(uint32 domain) view returns(address[] agents)
	GetActiveAgents(opts *bind.CallOpts, domain uint32) ([]common.Address, error)
	// GetAgent is a free data retrieval call binding the contract method 0x2de5aaf7.
	//
	// Solidity: function getAgent(uint256 index) view returns(address agent, (uint8,uint32,uint32) status)
	GetAgent(opts *bind.CallOpts, index *big.Int) (struct {
		Agent  common.Address
		Status AgentStatus
	}, error)
	// GetDispute is a free data retrieval call binding the contract method 0xe3a96cbd.
	//
	// Solidity: function getDispute(uint256 index) view returns(address guard, address notary, address slashedAgent, address fraudProver, bytes reportPayload, bytes reportSignature)
	GetDispute(opts *bind.CallOpts, index *big.Int) (struct {
		Guard           common.Address
		Notary          common.Address
		SlashedAgent    common.Address
		FraudProver     common.Address
		ReportPayload   []byte
		ReportSignature []byte
	}, error)
	// GetDisputesAmount is a free data retrieval call binding the contract method 0x3aaeccc6.
	//
	// Solidity: function getDisputesAmount() view returns(uint256)
	GetDisputesAmount(opts *bind.CallOpts) (*big.Int, error)
	// GetLeafs is a free data retrieval call binding the contract method 0x33d1b2e8.
	//
	// Solidity: function getLeafs(uint256 indexFrom, uint256 amount) view returns(bytes32[] leafs)
	GetLeafs(opts *bind.CallOpts, indexFrom *big.Int, amount *big.Int) ([][32]byte, error)
	// GetProof is a free data retrieval call binding the contract method 0x3eea79d1.
	//
	// Solidity: function getProof(address agent) view returns(bytes32[] proof)
	GetProof(opts *bind.CallOpts, agent common.Address) ([][32]byte, error)
	// Inbox is a free data retrieval call binding the contract method 0xfb0e722b.
	//
	// Solidity: function inbox() view returns(address)
	Inbox(opts *bind.CallOpts) (common.Address, error)
	// LeafsAmount is a free data retrieval call binding the contract method 0x33c3a8f3.
	//
	// Solidity: function leafsAmount() view returns(uint256 amount)
	LeafsAmount(opts *bind.CallOpts) (*big.Int, error)
	// LocalDomain is a free data retrieval call binding the contract method 0x8d3638f4.
	//
	// Solidity: function localDomain() view returns(uint32)
	LocalDomain(opts *bind.CallOpts) (uint32, error)
	// Origin is a free data retrieval call binding the contract method 0x938b5f32.
	//
	// Solidity: function origin() view returns(address)
	Origin(opts *bind.CallOpts) (common.Address, error)
	// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
	//
	// Solidity: function owner() view returns(address)
	Owner(opts *bind.CallOpts) (common.Address, error)
	// Summit is a free data retrieval call binding the contract method 0x9fbcb9cb.
	//
	// Solidity: function summit() view returns(address)
	Summit(opts *bind.CallOpts) (common.Address, error)
	// SynapseDomain is a free data retrieval call binding the contract method 0x717b8638.
	//
	// Solidity: function synapseDomain() view returns(uint32)
	SynapseDomain(opts *bind.CallOpts) (uint32, error)
	// Version is a free data retrieval call binding the contract method 0x54fd4d50.
	//
	// Solidity: function version() view returns(string versionString)
	Version(opts *bind.CallOpts) (string, error)
}
