// Code generated by mockery v2.9.4. DO NOT EDIT.

package mocks

import (
	big "math/big"

	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	common "github.com/ethereum/go-ethereum/common"

	event "github.com/ethereum/go-ethereum/event"

	mock "github.com/stretchr/testify/mock"

	origin "github.com/synapsecns/sanguine/agents/contracts/origin"

	types "github.com/ethereum/go-ethereum/core/types"
)

// IOrigin is an autogenerated mock type for the IOrigin type
type IOrigin struct {
	mock.Mock
}

// Address provides a mock function with given fields:
func (_m *IOrigin) Address() common.Address {
	ret := _m.Called()

	var r0 common.Address
	if rf, ok := ret.Get(0).(func() common.Address); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	return r0
}

// AllGuards provides a mock function with given fields: opts
func (_m *IOrigin) AllGuards(opts *bind.CallOpts) ([]common.Address, error) {
	ret := _m.Called(opts)

	var r0 []common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) []common.Address); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AllNotaries provides a mock function with given fields: opts
func (_m *IOrigin) AllNotaries(opts *bind.CallOpts) ([]common.Address, error) {
	ret := _m.Called(opts)

	var r0 []common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) []common.Address); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Count provides a mock function with given fields: opts
func (_m *IOrigin) Count(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Dispatch provides a mock function with given fields: opts, _destination, _recipientAddress, _optimisticSeconds, _tips, _messageBody
func (_m *IOrigin) Dispatch(opts *bind.TransactOpts, _destination uint32, _recipientAddress [32]byte, _optimisticSeconds uint32, _tips []byte, _messageBody []byte) (*types.Transaction, error) {
	ret := _m.Called(opts, _destination, _recipientAddress, _optimisticSeconds, _tips, _messageBody)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, uint32, [32]byte, uint32, []byte, []byte) *types.Transaction); ok {
		r0 = rf(opts, _destination, _recipientAddress, _optimisticSeconds, _tips, _messageBody)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, uint32, [32]byte, uint32, []byte, []byte) error); ok {
		r1 = rf(opts, _destination, _recipientAddress, _optimisticSeconds, _tips, _messageBody)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterDispatch provides a mock function with given fields: opts, messageHash, leafIndex, destinationAndNonce
func (_m *IOrigin) FilterDispatch(opts *bind.FilterOpts, messageHash [][32]byte, leafIndex []*big.Int, destinationAndNonce []uint64) (*origin.OriginDispatchIterator, error) {
	ret := _m.Called(opts, messageHash, leafIndex, destinationAndNonce)

	var r0 *origin.OriginDispatchIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts, [][32]byte, []*big.Int, []uint64) *origin.OriginDispatchIterator); ok {
		r0 = rf(opts, messageHash, leafIndex, destinationAndNonce)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDispatchIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts, [][32]byte, []*big.Int, []uint64) error); ok {
		r1 = rf(opts, messageHash, leafIndex, destinationAndNonce)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterDomainNotaryAdded provides a mock function with given fields: opts
func (_m *IOrigin) FilterDomainNotaryAdded(opts *bind.FilterOpts) (*origin.OriginDomainNotaryAddedIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginDomainNotaryAddedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginDomainNotaryAddedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDomainNotaryAddedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterDomainNotaryRemoved provides a mock function with given fields: opts
func (_m *IOrigin) FilterDomainNotaryRemoved(opts *bind.FilterOpts) (*origin.OriginDomainNotaryRemovedIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginDomainNotaryRemovedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginDomainNotaryRemovedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDomainNotaryRemovedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterGuardAdded provides a mock function with given fields: opts
func (_m *IOrigin) FilterGuardAdded(opts *bind.FilterOpts) (*origin.OriginGuardAddedIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginGuardAddedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginGuardAddedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginGuardAddedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterGuardRemoved provides a mock function with given fields: opts
func (_m *IOrigin) FilterGuardRemoved(opts *bind.FilterOpts) (*origin.OriginGuardRemovedIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginGuardRemovedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginGuardRemovedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginGuardRemovedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterImproperAttestation provides a mock function with given fields: opts
func (_m *IOrigin) FilterImproperAttestation(opts *bind.FilterOpts) (*origin.OriginImproperAttestationIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginImproperAttestationIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginImproperAttestationIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginImproperAttestationIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterInitialized provides a mock function with given fields: opts
func (_m *IOrigin) FilterInitialized(opts *bind.FilterOpts) (*origin.OriginInitializedIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginInitializedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginInitializedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginInitializedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterNewNotaryManager provides a mock function with given fields: opts
func (_m *IOrigin) FilterNewNotaryManager(opts *bind.FilterOpts) (*origin.OriginNewNotaryManagerIterator, error) {
	ret := _m.Called(opts)

	var r0 *origin.OriginNewNotaryManagerIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *origin.OriginNewNotaryManagerIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginNewNotaryManagerIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterNotarySlashed provides a mock function with given fields: opts, notary, reporter
func (_m *IOrigin) FilterNotarySlashed(opts *bind.FilterOpts, notary []common.Address, reporter []common.Address) (*origin.OriginNotarySlashedIterator, error) {
	ret := _m.Called(opts, notary, reporter)

	var r0 *origin.OriginNotarySlashedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts, []common.Address, []common.Address) *origin.OriginNotarySlashedIterator); ok {
		r0 = rf(opts, notary, reporter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginNotarySlashedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts, []common.Address, []common.Address) error); ok {
		r1 = rf(opts, notary, reporter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterOwnershipTransferred provides a mock function with given fields: opts, previousOwner, newOwner
func (_m *IOrigin) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*origin.OriginOwnershipTransferredIterator, error) {
	ret := _m.Called(opts, previousOwner, newOwner)

	var r0 *origin.OriginOwnershipTransferredIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts, []common.Address, []common.Address) *origin.OriginOwnershipTransferredIterator); ok {
		r0 = rf(opts, previousOwner, newOwner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginOwnershipTransferredIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts, []common.Address, []common.Address) error); ok {
		r1 = rf(opts, previousOwner, newOwner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGuard provides a mock function with given fields: opts, _index
func (_m *IOrigin) GetGuard(opts *bind.CallOpts, _index *big.Int) (common.Address, error) {
	ret := _m.Called(opts, _index)

	var r0 common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) common.Address); ok {
		r0 = rf(opts, _index)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, _index)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetNotary provides a mock function with given fields: opts, _index
func (_m *IOrigin) GetNotary(opts *bind.CallOpts, _index *big.Int) (common.Address, error) {
	ret := _m.Called(opts, _index)

	var r0 common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) common.Address); ok {
		r0 = rf(opts, _index)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, _index)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GuardsAmount provides a mock function with given fields: opts
func (_m *IOrigin) GuardsAmount(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// HistoricalRoots provides a mock function with given fields: opts, arg0
func (_m *IOrigin) HistoricalRoots(opts *bind.CallOpts, arg0 *big.Int) ([32]byte, error) {
	ret := _m.Called(opts, arg0)

	var r0 [32]byte
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) [32]byte); ok {
		r0 = rf(opts, arg0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([32]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, arg0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ImproperAttestation provides a mock function with given fields: opts, _attestation
func (_m *IOrigin) ImproperAttestation(opts *bind.TransactOpts, _attestation []byte) (*types.Transaction, error) {
	ret := _m.Called(opts, _attestation)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, []byte) *types.Transaction); ok {
		r0 = rf(opts, _attestation)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, []byte) error); ok {
		r1 = rf(opts, _attestation)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Initialize provides a mock function with given fields: opts, _notaryManager
func (_m *IOrigin) Initialize(opts *bind.TransactOpts, _notaryManager common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, _notaryManager)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address) *types.Transaction); ok {
		r0 = rf(opts, _notaryManager)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address) error); ok {
		r1 = rf(opts, _notaryManager)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LocalDomain provides a mock function with given fields: opts
func (_m *IOrigin) LocalDomain(opts *bind.CallOpts) (uint32, error) {
	ret := _m.Called(opts)

	var r0 uint32
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) uint32); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(uint32)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MAXMESSAGEBODYBYTES provides a mock function with given fields: opts
func (_m *IOrigin) MAXMESSAGEBODYBYTES(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Nonce provides a mock function with given fields: opts
func (_m *IOrigin) Nonce(opts *bind.CallOpts) (uint32, error) {
	ret := _m.Called(opts)

	var r0 uint32
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) uint32); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(uint32)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NotariesAmount provides a mock function with given fields: opts
func (_m *IOrigin) NotariesAmount(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NotaryManager provides a mock function with given fields: opts
func (_m *IOrigin) NotaryManager(opts *bind.CallOpts) (common.Address, error) {
	ret := _m.Called(opts)

	var r0 common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) common.Address); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Owner provides a mock function with given fields: opts
func (_m *IOrigin) Owner(opts *bind.CallOpts) (common.Address, error) {
	ret := _m.Called(opts)

	var r0 common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) common.Address); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseDispatch provides a mock function with given fields: log
func (_m *IOrigin) ParseDispatch(log types.Log) (*origin.OriginDispatch, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginDispatch
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginDispatch); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDispatch)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseDomainNotaryAdded provides a mock function with given fields: log
func (_m *IOrigin) ParseDomainNotaryAdded(log types.Log) (*origin.OriginDomainNotaryAdded, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginDomainNotaryAdded
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginDomainNotaryAdded); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDomainNotaryAdded)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseDomainNotaryRemoved provides a mock function with given fields: log
func (_m *IOrigin) ParseDomainNotaryRemoved(log types.Log) (*origin.OriginDomainNotaryRemoved, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginDomainNotaryRemoved
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginDomainNotaryRemoved); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginDomainNotaryRemoved)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseGuardAdded provides a mock function with given fields: log
func (_m *IOrigin) ParseGuardAdded(log types.Log) (*origin.OriginGuardAdded, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginGuardAdded
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginGuardAdded); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginGuardAdded)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseGuardRemoved provides a mock function with given fields: log
func (_m *IOrigin) ParseGuardRemoved(log types.Log) (*origin.OriginGuardRemoved, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginGuardRemoved
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginGuardRemoved); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginGuardRemoved)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseImproperAttestation provides a mock function with given fields: log
func (_m *IOrigin) ParseImproperAttestation(log types.Log) (*origin.OriginImproperAttestation, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginImproperAttestation
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginImproperAttestation); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginImproperAttestation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseInitialized provides a mock function with given fields: log
func (_m *IOrigin) ParseInitialized(log types.Log) (*origin.OriginInitialized, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginInitialized
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginInitialized); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginInitialized)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseNewNotaryManager provides a mock function with given fields: log
func (_m *IOrigin) ParseNewNotaryManager(log types.Log) (*origin.OriginNewNotaryManager, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginNewNotaryManager
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginNewNotaryManager); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginNewNotaryManager)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseNotarySlashed provides a mock function with given fields: log
func (_m *IOrigin) ParseNotarySlashed(log types.Log) (*origin.OriginNotarySlashed, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginNotarySlashed
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginNotarySlashed); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginNotarySlashed)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ParseOwnershipTransferred provides a mock function with given fields: log
func (_m *IOrigin) ParseOwnershipTransferred(log types.Log) (*origin.OriginOwnershipTransferred, error) {
	ret := _m.Called(log)

	var r0 *origin.OriginOwnershipTransferred
	if rf, ok := ret.Get(0).(func(types.Log) *origin.OriginOwnershipTransferred); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*origin.OriginOwnershipTransferred)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(types.Log) error); ok {
		r1 = rf(log)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Parser provides a mock function with given fields:
func (_m *IOrigin) Parser() origin.Parser {
	ret := _m.Called()

	var r0 origin.Parser
	if rf, ok := ret.Get(0).(func() origin.Parser); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(origin.Parser)
		}
	}

	return r0
}

// RenounceOwnership provides a mock function with given fields: opts
func (_m *IOrigin) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	ret := _m.Called(opts)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts) *types.Transaction); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Root provides a mock function with given fields: opts
func (_m *IOrigin) Root(opts *bind.CallOpts) ([32]byte, error) {
	ret := _m.Called(opts)

	var r0 [32]byte
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) [32]byte); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([32]byte)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetNotary provides a mock function with given fields: opts, _notary
func (_m *IOrigin) SetNotary(opts *bind.TransactOpts, _notary common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, _notary)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address) *types.Transaction); ok {
		r0 = rf(opts, _notary)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address) error); ok {
		r1 = rf(opts, _notary)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetNotaryManager provides a mock function with given fields: opts, _notaryManager
func (_m *IOrigin) SetNotaryManager(opts *bind.TransactOpts, _notaryManager common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, _notaryManager)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address) *types.Transaction); ok {
		r0 = rf(opts, _notaryManager)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address) error); ok {
		r1 = rf(opts, _notaryManager)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetSystemRouter provides a mock function with given fields: opts, _systemRouter
func (_m *IOrigin) SetSystemRouter(opts *bind.TransactOpts, _systemRouter common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, _systemRouter)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address) *types.Transaction); ok {
		r0 = rf(opts, _systemRouter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address) error); ok {
		r1 = rf(opts, _systemRouter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// State provides a mock function with given fields: opts
func (_m *IOrigin) State(opts *bind.CallOpts) (uint8, error) {
	ret := _m.Called(opts)

	var r0 uint8
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) uint8); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(uint8)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SuggestAttestation provides a mock function with given fields: opts
func (_m *IOrigin) SuggestAttestation(opts *bind.CallOpts) (struct {
	Nonce uint32
	Root  [32]byte
}, error) {
	ret := _m.Called(opts)

	var r0 struct {
		Nonce uint32
		Root  [32]byte
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) struct {
		Nonce uint32
		Root  [32]byte
	}); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(struct {
			Nonce uint32
			Root  [32]byte
		})
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SystemRouter provides a mock function with given fields: opts
func (_m *IOrigin) SystemRouter(opts *bind.CallOpts) (common.Address, error) {
	ret := _m.Called(opts)

	var r0 common.Address
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) common.Address); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(common.Address)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// TransferOwnership provides a mock function with given fields: opts, newOwner
func (_m *IOrigin) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, newOwner)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address) *types.Transaction); ok {
		r0 = rf(opts, newOwner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address) error); ok {
		r1 = rf(opts, newOwner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Tree provides a mock function with given fields: opts
func (_m *IOrigin) Tree(opts *bind.CallOpts) (*big.Int, error) {
	ret := _m.Called(opts)

	var r0 *big.Int
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) *big.Int); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*big.Int)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VERSION provides a mock function with given fields: opts
func (_m *IOrigin) VERSION(opts *bind.CallOpts) (uint8, error) {
	ret := _m.Called(opts)

	var r0 uint8
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) uint8); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(uint8)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchDispatch provides a mock function with given fields: opts, sink, messageHash, leafIndex, destinationAndNonce
func (_m *IOrigin) WatchDispatch(opts *bind.WatchOpts, sink chan<- *origin.OriginDispatch, messageHash [][32]byte, leafIndex []*big.Int, destinationAndNonce []uint64) (event.Subscription, error) {
	ret := _m.Called(opts, sink, messageHash, leafIndex, destinationAndNonce)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginDispatch, [][32]byte, []*big.Int, []uint64) event.Subscription); ok {
		r0 = rf(opts, sink, messageHash, leafIndex, destinationAndNonce)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginDispatch, [][32]byte, []*big.Int, []uint64) error); ok {
		r1 = rf(opts, sink, messageHash, leafIndex, destinationAndNonce)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchDomainNotaryAdded provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchDomainNotaryAdded(opts *bind.WatchOpts, sink chan<- *origin.OriginDomainNotaryAdded) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginDomainNotaryAdded) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginDomainNotaryAdded) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchDomainNotaryRemoved provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchDomainNotaryRemoved(opts *bind.WatchOpts, sink chan<- *origin.OriginDomainNotaryRemoved) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginDomainNotaryRemoved) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginDomainNotaryRemoved) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchGuardAdded provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchGuardAdded(opts *bind.WatchOpts, sink chan<- *origin.OriginGuardAdded) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginGuardAdded) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginGuardAdded) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchGuardRemoved provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchGuardRemoved(opts *bind.WatchOpts, sink chan<- *origin.OriginGuardRemoved) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginGuardRemoved) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginGuardRemoved) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchImproperAttestation provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchImproperAttestation(opts *bind.WatchOpts, sink chan<- *origin.OriginImproperAttestation) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginImproperAttestation) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginImproperAttestation) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchInitialized provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchInitialized(opts *bind.WatchOpts, sink chan<- *origin.OriginInitialized) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginInitialized) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginInitialized) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchNewNotaryManager provides a mock function with given fields: opts, sink
func (_m *IOrigin) WatchNewNotaryManager(opts *bind.WatchOpts, sink chan<- *origin.OriginNewNotaryManager) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginNewNotaryManager) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginNewNotaryManager) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchNotarySlashed provides a mock function with given fields: opts, sink, notary, reporter
func (_m *IOrigin) WatchNotarySlashed(opts *bind.WatchOpts, sink chan<- *origin.OriginNotarySlashed, notary []common.Address, reporter []common.Address) (event.Subscription, error) {
	ret := _m.Called(opts, sink, notary, reporter)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginNotarySlashed, []common.Address, []common.Address) event.Subscription); ok {
		r0 = rf(opts, sink, notary, reporter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginNotarySlashed, []common.Address, []common.Address) error); ok {
		r1 = rf(opts, sink, notary, reporter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchOwnershipTransferred provides a mock function with given fields: opts, sink, previousOwner, newOwner
func (_m *IOrigin) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *origin.OriginOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {
	ret := _m.Called(opts, sink, previousOwner, newOwner)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *origin.OriginOwnershipTransferred, []common.Address, []common.Address) event.Subscription); ok {
		r0 = rf(opts, sink, previousOwner, newOwner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *origin.OriginOwnershipTransferred, []common.Address, []common.Address) error); ok {
		r1 = rf(opts, sink, previousOwner, newOwner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
