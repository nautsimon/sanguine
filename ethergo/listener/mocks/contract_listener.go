// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	context "context"

	common "github.com/ethereum/go-ethereum/common"

	listener "github.com/synapsecns/sanguine/ethergo/listener"

	mock "github.com/stretchr/testify/mock"
)

// ContractListener is an autogenerated mock type for the ContractListener type
type ContractListener struct {
	mock.Mock
}

// Address provides a mock function with given fields:
func (_m *ContractListener) Address() common.Address {
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

// LatestBlock provides a mock function with given fields:
func (_m *ContractListener) LatestBlock() uint64 {
	ret := _m.Called()

	var r0 uint64
	if rf, ok := ret.Get(0).(func() uint64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(uint64)
	}

	return r0
}

// Listen provides a mock function with given fields: ctx, handler
func (_m *ContractListener) Listen(ctx context.Context, handler listener.HandleLog) error {
	ret := _m.Called(ctx, handler)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, listener.HandleLog) error); ok {
		r0 = rf(ctx, handler)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewContractListener interface {
	mock.TestingT
	Cleanup(func())
}

// NewContractListener creates a new instance of ContractListener. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewContractListener(t mockConstructorTestingTNewContractListener) *ContractListener {
	mock := &ContractListener{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
