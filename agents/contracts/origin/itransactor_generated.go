// autogenerated file

package origin

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// IOriginTransactor ...
type IOriginTransactor interface {
	// AddGuard is a paid mutator transaction binding the contract method 0x6913a63c.
	//
	// Solidity: function addGuard(address _guard) returns(bool)
	AddGuard(opts *bind.TransactOpts, _guard common.Address) (*types.Transaction, error)
	// AddNotary is a paid mutator transaction binding the contract method 0x2af678b0.
	//
	// Solidity: function addNotary(uint32 _domain, address _notary) returns(bool)
	AddNotary(opts *bind.TransactOpts, _domain uint32, _notary common.Address) (*types.Transaction, error)
	// Dispatch is a paid mutator transaction binding the contract method 0xf7560e40.
	//
	// Solidity: function dispatch(uint32 _destination, bytes32 _recipient, uint32 _optimisticSeconds, bytes _tips, bytes _messageBody) payable returns(uint32 messageNonce, bytes32 messageHash)
	Dispatch(opts *bind.TransactOpts, _destination uint32, _recipient [32]byte, _optimisticSeconds uint32, _tips []byte, _messageBody []byte) (*types.Transaction, error)
	// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
	//
	// Solidity: function initialize() returns()
	Initialize(opts *bind.TransactOpts) (*types.Transaction, error)
	// RemoveGuard is a paid mutator transaction binding the contract method 0xb6235016.
	//
	// Solidity: function removeGuard(address _guard) returns(bool)
	RemoveGuard(opts *bind.TransactOpts, _guard common.Address) (*types.Transaction, error)
	// RemoveNotary is a paid mutator transaction binding the contract method 0x4b82bad7.
	//
	// Solidity: function removeNotary(uint32 _domain, address _notary) returns(bool)
	RemoveNotary(opts *bind.TransactOpts, _domain uint32, _notary common.Address) (*types.Transaction, error)
	// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
	//
	// Solidity: function renounceOwnership() returns()
	RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error)
	// SetSystemRouter is a paid mutator transaction binding the contract method 0xfbde22f7.
	//
	// Solidity: function setSystemRouter(address _systemRouter) returns()
	SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error)
	// SlashAgent is a paid mutator transaction binding the contract method 0x11ebc1ad.
	//
	// Solidity: function slashAgent(uint256 , uint32 _callOrigin, uint8 _caller, (uint8,bool,uint32,address) _info) returns()
	SlashAgent(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _info SystemContractAgentInfo) (*types.Transaction, error)
	// SubmitAttestation is a paid mutator transaction binding the contract method 0xf646a512.
	//
	// Solidity: function submitAttestation(bytes _attestation) returns(bool)
	SubmitAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error)
	// SubmitReport is a paid mutator transaction binding the contract method 0x5815869d.
	//
	// Solidity: function submitReport(bytes _report) returns(bool)
	SubmitReport(opts *bind.TransactOpts, _report []byte) (*types.Transaction, error)
	// SyncAgents is a paid mutator transaction binding the contract method 0x86cd8f91.
	//
	// Solidity: function syncAgents(uint256 , uint32 _callOrigin, uint8 _caller, uint256 _requestID, bool _removeExisting, (uint8,bool,uint32,address)[] _infos) returns()
	SyncAgents(opts *bind.TransactOpts, arg0 *big.Int, _callOrigin uint32, _caller uint8, _requestID *big.Int, _removeExisting bool, _infos []SystemContractAgentInfo) (*types.Transaction, error)
	// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
	//
	// Solidity: function transferOwnership(address newOwner) returns()
	TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error)
}
