// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	big "math/big"

	bind "github.com/ethereum/go-ethereum/accounts/abi/bind"
	common "github.com/ethereum/go-ethereum/common"

	event "github.com/ethereum/go-ethereum/event"

	lightmanager "github.com/synapsecns/sanguine/agents/contracts/lightmanager"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// ILightManager is an autogenerated mock type for the ILightManager type
type ILightManager struct {
	mock.Mock
}

// Address provides a mock function with given fields:
func (_m *ILightManager) Address() common.Address {
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

// AgentRoot provides a mock function with given fields: opts
func (_m *ILightManager) AgentRoot(opts *bind.CallOpts) ([32]byte, error) {
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

// AgentStatus provides a mock function with given fields: opts, agent
func (_m *ILightManager) AgentStatus(opts *bind.CallOpts, agent common.Address) (lightmanager.AgentStatus, error) {
	ret := _m.Called(opts, agent)

	var r0 lightmanager.AgentStatus
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, common.Address) lightmanager.AgentStatus); ok {
		r0 = rf(opts, agent)
	} else {
		r0 = ret.Get(0).(lightmanager.AgentStatus)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, common.Address) error); ok {
		r1 = rf(opts, agent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Destination provides a mock function with given fields: opts
func (_m *ILightManager) Destination(opts *bind.CallOpts) (common.Address, error) {
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

// DisputeStatus provides a mock function with given fields: opts, agent
func (_m *ILightManager) DisputeStatus(opts *bind.CallOpts, agent common.Address) (struct {
	Flag        uint8
	Rival       common.Address
	FraudProver common.Address
	DisputePtr  *big.Int
}, error) {
	ret := _m.Called(opts, agent)

	var r0 struct {
		Flag        uint8
		Rival       common.Address
		FraudProver common.Address
		DisputePtr  *big.Int
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, common.Address) struct {
		Flag        uint8
		Rival       common.Address
		FraudProver common.Address
		DisputePtr  *big.Int
	}); ok {
		r0 = rf(opts, agent)
	} else {
		r0 = ret.Get(0).(struct {
			Flag        uint8
			Rival       common.Address
			FraudProver common.Address
			DisputePtr  *big.Int
		})
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, common.Address) error); ok {
		r1 = rf(opts, agent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FilterDisputeOpened provides a mock function with given fields: opts
func (_m *ILightManager) FilterDisputeOpened(opts *bind.FilterOpts) (*lightmanager.LightManagerDisputeOpenedIterator, error) {
	ret := _m.Called(opts)

	var r0 *lightmanager.LightManagerDisputeOpenedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *lightmanager.LightManagerDisputeOpenedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerDisputeOpenedIterator)
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

// FilterDisputeResolved provides a mock function with given fields: opts
func (_m *ILightManager) FilterDisputeResolved(opts *bind.FilterOpts) (*lightmanager.LightManagerDisputeResolvedIterator, error) {
	ret := _m.Called(opts)

	var r0 *lightmanager.LightManagerDisputeResolvedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *lightmanager.LightManagerDisputeResolvedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerDisputeResolvedIterator)
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
func (_m *ILightManager) FilterInitialized(opts *bind.FilterOpts) (*lightmanager.LightManagerInitializedIterator, error) {
	ret := _m.Called(opts)

	var r0 *lightmanager.LightManagerInitializedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *lightmanager.LightManagerInitializedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerInitializedIterator)
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

// FilterOwnershipTransferred provides a mock function with given fields: opts, previousOwner, newOwner
func (_m *ILightManager) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*lightmanager.LightManagerOwnershipTransferredIterator, error) {
	ret := _m.Called(opts, previousOwner, newOwner)

	var r0 *lightmanager.LightManagerOwnershipTransferredIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts, []common.Address, []common.Address) *lightmanager.LightManagerOwnershipTransferredIterator); ok {
		r0 = rf(opts, previousOwner, newOwner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerOwnershipTransferredIterator)
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

// FilterRootUpdated provides a mock function with given fields: opts
func (_m *ILightManager) FilterRootUpdated(opts *bind.FilterOpts) (*lightmanager.LightManagerRootUpdatedIterator, error) {
	ret := _m.Called(opts)

	var r0 *lightmanager.LightManagerRootUpdatedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts) *lightmanager.LightManagerRootUpdatedIterator); ok {
		r0 = rf(opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerRootUpdatedIterator)
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

// FilterStatusUpdated provides a mock function with given fields: opts, domain, agent
func (_m *ILightManager) FilterStatusUpdated(opts *bind.FilterOpts, domain []uint32, agent []common.Address) (*lightmanager.LightManagerStatusUpdatedIterator, error) {
	ret := _m.Called(opts, domain, agent)

	var r0 *lightmanager.LightManagerStatusUpdatedIterator
	if rf, ok := ret.Get(0).(func(*bind.FilterOpts, []uint32, []common.Address) *lightmanager.LightManagerStatusUpdatedIterator); ok {
		r0 = rf(opts, domain, agent)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerStatusUpdatedIterator)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.FilterOpts, []uint32, []common.Address) error); ok {
		r1 = rf(opts, domain, agent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAgent provides a mock function with given fields: opts, index
func (_m *ILightManager) GetAgent(opts *bind.CallOpts, index *big.Int) (struct {
	Agent  common.Address
	Status lightmanager.AgentStatus
}, error) {
	ret := _m.Called(opts, index)

	var r0 struct {
		Agent  common.Address
		Status lightmanager.AgentStatus
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) struct {
		Agent  common.Address
		Status lightmanager.AgentStatus
	}); ok {
		r0 = rf(opts, index)
	} else {
		r0 = ret.Get(0).(struct {
			Agent  common.Address
			Status lightmanager.AgentStatus
		})
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, index)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDispute provides a mock function with given fields: opts, index
func (_m *ILightManager) GetDispute(opts *bind.CallOpts, index *big.Int) (struct {
	Guard           common.Address
	Notary          common.Address
	SlashedAgent    common.Address
	FraudProver     common.Address
	ReportPayload   []byte
	ReportSignature []byte
}, error) {
	ret := _m.Called(opts, index)

	var r0 struct {
		Guard           common.Address
		Notary          common.Address
		SlashedAgent    common.Address
		FraudProver     common.Address
		ReportPayload   []byte
		ReportSignature []byte
	}
	if rf, ok := ret.Get(0).(func(*bind.CallOpts, *big.Int) struct {
		Guard           common.Address
		Notary          common.Address
		SlashedAgent    common.Address
		FraudProver     common.Address
		ReportPayload   []byte
		ReportSignature []byte
	}); ok {
		r0 = rf(opts, index)
	} else {
		r0 = ret.Get(0).(struct {
			Guard           common.Address
			Notary          common.Address
			SlashedAgent    common.Address
			FraudProver     common.Address
			ReportPayload   []byte
			ReportSignature []byte
		})
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts, *big.Int) error); ok {
		r1 = rf(opts, index)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDisputesAmount provides a mock function with given fields: opts
func (_m *ILightManager) GetDisputesAmount(opts *bind.CallOpts) (*big.Int, error) {
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

// Inbox provides a mock function with given fields: opts
func (_m *ILightManager) Inbox(opts *bind.CallOpts) (common.Address, error) {
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

// Initialize provides a mock function with given fields: opts, origin_, destination_, inbox_
func (_m *ILightManager) Initialize(opts *bind.TransactOpts, origin_ common.Address, destination_ common.Address, inbox_ common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, origin_, destination_, inbox_)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, common.Address, common.Address) *types.Transaction); ok {
		r0 = rf(opts, origin_, destination_, inbox_)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address, common.Address, common.Address) error); ok {
		r1 = rf(opts, origin_, destination_, inbox_)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LocalDomain provides a mock function with given fields: opts
func (_m *ILightManager) LocalDomain(opts *bind.CallOpts) (uint32, error) {
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

// Multicall provides a mock function with given fields: opts, calls
func (_m *ILightManager) Multicall(opts *bind.TransactOpts, calls []lightmanager.MultiCallableCall) (*types.Transaction, error) {
	ret := _m.Called(opts, calls)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, []lightmanager.MultiCallableCall) *types.Transaction); ok {
		r0 = rf(opts, calls)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, []lightmanager.MultiCallableCall) error); ok {
		r1 = rf(opts, calls)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OpenDispute provides a mock function with given fields: opts, guardIndex, notaryIndex
func (_m *ILightManager) OpenDispute(opts *bind.TransactOpts, guardIndex uint32, notaryIndex uint32) (*types.Transaction, error) {
	ret := _m.Called(opts, guardIndex, notaryIndex)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, uint32, uint32) *types.Transaction); ok {
		r0 = rf(opts, guardIndex, notaryIndex)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, uint32, uint32) error); ok {
		r1 = rf(opts, guardIndex, notaryIndex)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Origin provides a mock function with given fields: opts
func (_m *ILightManager) Origin(opts *bind.CallOpts) (common.Address, error) {
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
func (_m *ILightManager) Owner(opts *bind.CallOpts) (common.Address, error) {
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

// ParseDisputeOpened provides a mock function with given fields: log
func (_m *ILightManager) ParseDisputeOpened(log types.Log) (*lightmanager.LightManagerDisputeOpened, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerDisputeOpened
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerDisputeOpened); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerDisputeOpened)
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

// ParseDisputeResolved provides a mock function with given fields: log
func (_m *ILightManager) ParseDisputeResolved(log types.Log) (*lightmanager.LightManagerDisputeResolved, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerDisputeResolved
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerDisputeResolved); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerDisputeResolved)
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
func (_m *ILightManager) ParseInitialized(log types.Log) (*lightmanager.LightManagerInitialized, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerInitialized
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerInitialized); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerInitialized)
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
func (_m *ILightManager) ParseOwnershipTransferred(log types.Log) (*lightmanager.LightManagerOwnershipTransferred, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerOwnershipTransferred
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerOwnershipTransferred); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerOwnershipTransferred)
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

// ParseRootUpdated provides a mock function with given fields: log
func (_m *ILightManager) ParseRootUpdated(log types.Log) (*lightmanager.LightManagerRootUpdated, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerRootUpdated
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerRootUpdated); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerRootUpdated)
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

// ParseStatusUpdated provides a mock function with given fields: log
func (_m *ILightManager) ParseStatusUpdated(log types.Log) (*lightmanager.LightManagerStatusUpdated, error) {
	ret := _m.Called(log)

	var r0 *lightmanager.LightManagerStatusUpdated
	if rf, ok := ret.Get(0).(func(types.Log) *lightmanager.LightManagerStatusUpdated); ok {
		r0 = rf(log)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*lightmanager.LightManagerStatusUpdated)
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

// RemoteWithdrawTips provides a mock function with given fields: opts, msgOrigin, proofMaturity, recipient, amount
func (_m *ILightManager) RemoteWithdrawTips(opts *bind.TransactOpts, msgOrigin uint32, proofMaturity *big.Int, recipient common.Address, amount *big.Int) (*types.Transaction, error) {
	ret := _m.Called(opts, msgOrigin, proofMaturity, recipient, amount)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, uint32, *big.Int, common.Address, *big.Int) *types.Transaction); ok {
		r0 = rf(opts, msgOrigin, proofMaturity, recipient, amount)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, uint32, *big.Int, common.Address, *big.Int) error); ok {
		r1 = rf(opts, msgOrigin, proofMaturity, recipient, amount)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RenounceOwnership provides a mock function with given fields: opts
func (_m *ILightManager) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
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

// ResolveStuckDispute provides a mock function with given fields: opts, domain, slashedAgent
func (_m *ILightManager) ResolveStuckDispute(opts *bind.TransactOpts, domain uint32, slashedAgent common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, domain, slashedAgent)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, uint32, common.Address) *types.Transaction); ok {
		r0 = rf(opts, domain, slashedAgent)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, uint32, common.Address) error); ok {
		r1 = rf(opts, domain, slashedAgent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SetAgentRoot provides a mock function with given fields: opts, agentRoot_
func (_m *ILightManager) SetAgentRoot(opts *bind.TransactOpts, agentRoot_ [32]byte) (*types.Transaction, error) {
	ret := _m.Called(opts, agentRoot_)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, [32]byte) *types.Transaction); ok {
		r0 = rf(opts, agentRoot_)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, [32]byte) error); ok {
		r1 = rf(opts, agentRoot_)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SlashAgent provides a mock function with given fields: opts, domain, agent, prover
func (_m *ILightManager) SlashAgent(opts *bind.TransactOpts, domain uint32, agent common.Address, prover common.Address) (*types.Transaction, error) {
	ret := _m.Called(opts, domain, agent, prover)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, uint32, common.Address, common.Address) *types.Transaction); ok {
		r0 = rf(opts, domain, agent, prover)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, uint32, common.Address, common.Address) error); ok {
		r1 = rf(opts, domain, agent, prover)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SynapseDomain provides a mock function with given fields: opts
func (_m *ILightManager) SynapseDomain(opts *bind.CallOpts) (uint32, error) {
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

// TransferOwnership provides a mock function with given fields: opts, newOwner
func (_m *ILightManager) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
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

// UpdateAgentStatus provides a mock function with given fields: opts, agent, status, proof
func (_m *ILightManager) UpdateAgentStatus(opts *bind.TransactOpts, agent common.Address, status lightmanager.AgentStatus, proof [][32]byte) (*types.Transaction, error) {
	ret := _m.Called(opts, agent, status, proof)

	var r0 *types.Transaction
	if rf, ok := ret.Get(0).(func(*bind.TransactOpts, common.Address, lightmanager.AgentStatus, [][32]byte) *types.Transaction); ok {
		r0 = rf(opts, agent, status, proof)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.TransactOpts, common.Address, lightmanager.AgentStatus, [][32]byte) error); ok {
		r1 = rf(opts, agent, status, proof)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Version provides a mock function with given fields: opts
func (_m *ILightManager) Version(opts *bind.CallOpts) (string, error) {
	ret := _m.Called(opts)

	var r0 string
	if rf, ok := ret.Get(0).(func(*bind.CallOpts) string); ok {
		r0 = rf(opts)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.CallOpts) error); ok {
		r1 = rf(opts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchDisputeOpened provides a mock function with given fields: opts, sink
func (_m *ILightManager) WatchDisputeOpened(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerDisputeOpened) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerDisputeOpened) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerDisputeOpened) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchDisputeResolved provides a mock function with given fields: opts, sink
func (_m *ILightManager) WatchDisputeResolved(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerDisputeResolved) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerDisputeResolved) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerDisputeResolved) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchInitialized provides a mock function with given fields: opts, sink
func (_m *ILightManager) WatchInitialized(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerInitialized) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerInitialized) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerInitialized) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchOwnershipTransferred provides a mock function with given fields: opts, sink, previousOwner, newOwner
func (_m *ILightManager) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {
	ret := _m.Called(opts, sink, previousOwner, newOwner)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerOwnershipTransferred, []common.Address, []common.Address) event.Subscription); ok {
		r0 = rf(opts, sink, previousOwner, newOwner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerOwnershipTransferred, []common.Address, []common.Address) error); ok {
		r1 = rf(opts, sink, previousOwner, newOwner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchRootUpdated provides a mock function with given fields: opts, sink
func (_m *ILightManager) WatchRootUpdated(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerRootUpdated) (event.Subscription, error) {
	ret := _m.Called(opts, sink)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerRootUpdated) event.Subscription); ok {
		r0 = rf(opts, sink)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerRootUpdated) error); ok {
		r1 = rf(opts, sink)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// WatchStatusUpdated provides a mock function with given fields: opts, sink, domain, agent
func (_m *ILightManager) WatchStatusUpdated(opts *bind.WatchOpts, sink chan<- *lightmanager.LightManagerStatusUpdated, domain []uint32, agent []common.Address) (event.Subscription, error) {
	ret := _m.Called(opts, sink, domain, agent)

	var r0 event.Subscription
	if rf, ok := ret.Get(0).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerStatusUpdated, []uint32, []common.Address) event.Subscription); ok {
		r0 = rf(opts, sink, domain, agent)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Subscription)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*bind.WatchOpts, chan<- *lightmanager.LightManagerStatusUpdated, []uint32, []common.Address) error); ok {
		r1 = rf(opts, sink, domain, agent)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewILightManager interface {
	mock.TestingT
	Cleanup(func())
}

// NewILightManager creates a new instance of ILightManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewILightManager(t mockConstructorTestingTNewILightManager) *ILightManager {
	mock := &ILightManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
