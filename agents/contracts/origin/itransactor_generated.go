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
	// Initialize is a paid mutator transaction binding the contract method 0x8129fc1c.
	//
	// Solidity: function initialize() returns()
	Initialize(opts *bind.TransactOpts) (*types.Transaction, error)
	// ManagerSlash is a paid mutator transaction binding the contract method 0x5f7bd144.
	//
	// Solidity: function managerSlash(uint32 domain, address agent, address prover) returns()
	ManagerSlash(opts *bind.TransactOpts, domain uint32, agent common.Address, prover common.Address) (*types.Transaction, error)
	// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
	//
	// Solidity: function renounceOwnership() returns()
	RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error)
	// SendBaseMessage is a paid mutator transaction binding the contract method 0xf71c4347.
	//
	// Solidity: function sendBaseMessage(uint32 destination, bytes32 recipient, uint32 optimisticPeriod, uint256 paddedTips, uint256 paddedRequest, bytes content) payable returns(uint32 messageNonce, bytes32 messageHash)
	SendBaseMessage(opts *bind.TransactOpts, destination uint32, recipient [32]byte, optimisticPeriod uint32, paddedTips *big.Int, paddedRequest *big.Int, content []byte) (*types.Transaction, error)
	// SendManagerMessage is a paid mutator transaction binding the contract method 0xa1c702a7.
	//
	// Solidity: function sendManagerMessage(uint32 destination, uint32 optimisticPeriod, bytes payload) returns(uint32 messageNonce, bytes32 messageHash)
	SendManagerMessage(opts *bind.TransactOpts, destination uint32, optimisticPeriod uint32, payload []byte) (*types.Transaction, error)
	// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
	//
	// Solidity: function transferOwnership(address newOwner) returns()
	TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error)
	// WithdrawTips is a paid mutator transaction binding the contract method 0x4e04e7a7.
	//
	// Solidity: function withdrawTips(address recipient, uint256 amount) returns()
	WithdrawTips(opts *bind.TransactOpts, recipient common.Address, amount *big.Int) (*types.Transaction, error)
}
