// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	context "context"

	common "github.com/ethereum/go-ethereum/common"

	db "github.com/synapsecns/sanguine/services/scribe/db"

	mock "github.com/stretchr/testify/mock"

	types "github.com/ethereum/go-ethereum/core/types"
)

// EventDB is an autogenerated mock type for the EventDB type
type EventDB struct {
	mock.Mock
}

// ConfirmEthTxsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) ConfirmEthTxsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfirmEthTxsInRange provides a mock function with given fields: ctx, startBlock, endBlock, chainID
func (_m *EventDB) ConfirmEthTxsInRange(ctx context.Context, startBlock uint64, endBlock uint64, chainID uint32) error {
	ret := _m.Called(ctx, startBlock, endBlock, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64, uint64, uint32) error); ok {
		r0 = rf(ctx, startBlock, endBlock, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfirmLogsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) ConfirmLogsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfirmLogsInRange provides a mock function with given fields: ctx, startBlock, endBlock, chainID
func (_m *EventDB) ConfirmLogsInRange(ctx context.Context, startBlock uint64, endBlock uint64, chainID uint32) error {
	ret := _m.Called(ctx, startBlock, endBlock, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64, uint64, uint32) error); ok {
		r0 = rf(ctx, startBlock, endBlock, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfirmReceiptsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) ConfirmReceiptsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfirmReceiptsInRange provides a mock function with given fields: ctx, startBlock, endBlock, chainID
func (_m *EventDB) ConfirmReceiptsInRange(ctx context.Context, startBlock uint64, endBlock uint64, chainID uint32) error {
	ret := _m.Called(ctx, startBlock, endBlock, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64, uint64, uint32) error); ok {
		r0 = rf(ctx, startBlock, endBlock, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteEthTxsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) DeleteEthTxsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLogsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) DeleteLogsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteReceiptsForBlockHash provides a mock function with given fields: ctx, blockHash, chainID
func (_m *EventDB) DeleteReceiptsForBlockHash(ctx context.Context, blockHash common.Hash, chainID uint32) error {
	ret := _m.Called(ctx, blockHash, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Hash, uint32) error); ok {
		r0 = rf(ctx, blockHash, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RetrieveBlockTime provides a mock function with given fields: ctx, chainID, blockNumber
func (_m *EventDB) RetrieveBlockTime(ctx context.Context, chainID uint32, blockNumber uint64) (uint64, error) {
	ret := _m.Called(ctx, chainID, blockNumber)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context, uint32, uint64) uint64); ok {
		r0 = rf(ctx, chainID, blockNumber)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint32, uint64) error); ok {
		r1 = rf(ctx, chainID, blockNumber)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveBlockTimesCountForChain provides a mock function with given fields: ctx, chainID
func (_m *EventDB) RetrieveBlockTimesCountForChain(ctx context.Context, chainID uint32) (int64, error) {
	ret := _m.Called(ctx, chainID)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, uint32) int64); ok {
		r0 = rf(ctx, chainID)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint32) error); ok {
		r1 = rf(ctx, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveEthTxsInRange provides a mock function with given fields: ctx, ethTxFilter, startBlock, endBlock, page
func (_m *EventDB) RetrieveEthTxsInRange(ctx context.Context, ethTxFilter db.EthTxFilter, startBlock uint64, endBlock uint64, page int) ([]types.Transaction, error) {
	ret := _m.Called(ctx, ethTxFilter, startBlock, endBlock, page)

	var r0 []types.Transaction
	if rf, ok := ret.Get(0).(func(context.Context, db.EthTxFilter, uint64, uint64, int) []types.Transaction); ok {
		r0 = rf(ctx, ethTxFilter, startBlock, endBlock, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.EthTxFilter, uint64, uint64, int) error); ok {
		r1 = rf(ctx, ethTxFilter, startBlock, endBlock, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveEthTxsWithFilter provides a mock function with given fields: ctx, ethTxFilter, page
func (_m *EventDB) RetrieveEthTxsWithFilter(ctx context.Context, ethTxFilter db.EthTxFilter, page int) ([]types.Transaction, error) {
	ret := _m.Called(ctx, ethTxFilter, page)

	var r0 []types.Transaction
	if rf, ok := ret.Get(0).(func(context.Context, db.EthTxFilter, int) []types.Transaction); ok {
		r0 = rf(ctx, ethTxFilter, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]types.Transaction)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.EthTxFilter, int) error); ok {
		r1 = rf(ctx, ethTxFilter, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveFirstBlockStored provides a mock function with given fields: ctx, chainID
func (_m *EventDB) RetrieveFirstBlockStored(ctx context.Context, chainID uint32) (uint64, error) {
	ret := _m.Called(ctx, chainID)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context, uint32) uint64); ok {
		r0 = rf(ctx, chainID)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint32) error); ok {
		r1 = rf(ctx, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLastBlockStored provides a mock function with given fields: ctx, chainID
func (_m *EventDB) RetrieveLastBlockStored(ctx context.Context, chainID uint32) (uint64, error) {
	ret := _m.Called(ctx, chainID)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context, uint32) uint64); ok {
		r0 = rf(ctx, chainID)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint32) error); ok {
		r1 = rf(ctx, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLastConfirmedBlock provides a mock function with given fields: ctx, chainID
func (_m *EventDB) RetrieveLastConfirmedBlock(ctx context.Context, chainID uint32) (uint64, error) {
	ret := _m.Called(ctx, chainID)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context, uint32) uint64); ok {
		r0 = rf(ctx, chainID)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint32) error); ok {
		r1 = rf(ctx, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLastIndexed provides a mock function with given fields: ctx, contractAddress, chainID
func (_m *EventDB) RetrieveLastIndexed(ctx context.Context, contractAddress common.Address, chainID uint32) (uint64, error) {
	ret := _m.Called(ctx, contractAddress, chainID)

	var r0 uint64
	if rf, ok := ret.Get(0).(func(context.Context, common.Address, uint32) uint64); ok {
		r0 = rf(ctx, contractAddress, chainID)
	} else {
		r0 = ret.Get(0).(uint64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, common.Address, uint32) error); ok {
		r1 = rf(ctx, contractAddress, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLogCountForContract provides a mock function with given fields: ctx, contractAddress, chainID
func (_m *EventDB) RetrieveLogCountForContract(ctx context.Context, contractAddress common.Address, chainID uint32) (int64, error) {
	ret := _m.Called(ctx, contractAddress, chainID)

	var r0 int64
	if rf, ok := ret.Get(0).(func(context.Context, common.Address, uint32) int64); ok {
		r0 = rf(ctx, contractAddress, chainID)
	} else {
		r0 = ret.Get(0).(int64)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, common.Address, uint32) error); ok {
		r1 = rf(ctx, contractAddress, chainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLogsInRange provides a mock function with given fields: ctx, logFilter, startBlock, endBlock, page
func (_m *EventDB) RetrieveLogsInRange(ctx context.Context, logFilter db.LogFilter, startBlock uint64, endBlock uint64, page int) ([]*types.Log, error) {
	ret := _m.Called(ctx, logFilter, startBlock, endBlock, page)

	var r0 []*types.Log
	if rf, ok := ret.Get(0).(func(context.Context, db.LogFilter, uint64, uint64, int) []*types.Log); ok {
		r0 = rf(ctx, logFilter, startBlock, endBlock, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*types.Log)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.LogFilter, uint64, uint64, int) error); ok {
		r1 = rf(ctx, logFilter, startBlock, endBlock, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLogsWithFilter provides a mock function with given fields: ctx, logFilter, page
func (_m *EventDB) RetrieveLogsWithFilter(ctx context.Context, logFilter db.LogFilter, page int) ([]*types.Log, error) {
	ret := _m.Called(ctx, logFilter, page)

	var r0 []*types.Log
	if rf, ok := ret.Get(0).(func(context.Context, db.LogFilter, int) []*types.Log); ok {
		r0 = rf(ctx, logFilter, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*types.Log)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.LogFilter, int) error); ok {
		r1 = rf(ctx, logFilter, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveReceiptsInRange provides a mock function with given fields: ctx, receiptFilter, startBlock, endBlock, page
func (_m *EventDB) RetrieveReceiptsInRange(ctx context.Context, receiptFilter db.ReceiptFilter, startBlock uint64, endBlock uint64, page int) ([]types.Receipt, error) {
	ret := _m.Called(ctx, receiptFilter, startBlock, endBlock, page)

	var r0 []types.Receipt
	if rf, ok := ret.Get(0).(func(context.Context, db.ReceiptFilter, uint64, uint64, int) []types.Receipt); ok {
		r0 = rf(ctx, receiptFilter, startBlock, endBlock, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]types.Receipt)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.ReceiptFilter, uint64, uint64, int) error); ok {
		r1 = rf(ctx, receiptFilter, startBlock, endBlock, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveReceiptsWithFilter provides a mock function with given fields: ctx, receiptFilter, page
func (_m *EventDB) RetrieveReceiptsWithFilter(ctx context.Context, receiptFilter db.ReceiptFilter, page int) ([]types.Receipt, error) {
	ret := _m.Called(ctx, receiptFilter, page)

	var r0 []types.Receipt
	if rf, ok := ret.Get(0).(func(context.Context, db.ReceiptFilter, int) []types.Receipt); ok {
		r0 = rf(ctx, receiptFilter, page)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]types.Receipt)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, db.ReceiptFilter, int) error); ok {
		r1 = rf(ctx, receiptFilter, page)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StoreBlockTime provides a mock function with given fields: ctx, chainID, blockNumber, timestamp
func (_m *EventDB) StoreBlockTime(ctx context.Context, chainID uint32, blockNumber uint64, timestamp uint64) error {
	ret := _m.Called(ctx, chainID, blockNumber, timestamp)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint32, uint64, uint64) error); ok {
		r0 = rf(ctx, chainID, blockNumber, timestamp)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreEthTx provides a mock function with given fields: ctx, tx, chainID, blockHash, blockNumber, transactionIndex
func (_m *EventDB) StoreEthTx(ctx context.Context, tx *types.Transaction, chainID uint32, blockHash common.Hash, blockNumber uint64, transactionIndex uint64) error {
	ret := _m.Called(ctx, tx, chainID, blockHash, blockNumber, transactionIndex)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *types.Transaction, uint32, common.Hash, uint64, uint64) error); ok {
		r0 = rf(ctx, tx, chainID, blockHash, blockNumber, transactionIndex)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreLastBlockTime provides a mock function with given fields: ctx, chainID, blockNumber
func (_m *EventDB) StoreLastBlockTime(ctx context.Context, chainID uint32, blockNumber uint64) error {
	ret := _m.Called(ctx, chainID, blockNumber)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint32, uint64) error); ok {
		r0 = rf(ctx, chainID, blockNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreLastConfirmedBlock provides a mock function with given fields: ctx, chainID, blockNumber
func (_m *EventDB) StoreLastConfirmedBlock(ctx context.Context, chainID uint32, blockNumber uint64) error {
	ret := _m.Called(ctx, chainID, blockNumber)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint32, uint64) error); ok {
		r0 = rf(ctx, chainID, blockNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreLastIndexed provides a mock function with given fields: ctx, contractAddress, chainID, blockNumber
func (_m *EventDB) StoreLastIndexed(ctx context.Context, contractAddress common.Address, chainID uint32, blockNumber uint64) error {
	ret := _m.Called(ctx, contractAddress, chainID, blockNumber)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, common.Address, uint32, uint64) error); ok {
		r0 = rf(ctx, contractAddress, chainID, blockNumber)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreLog provides a mock function with given fields: ctx, log, chainID
func (_m *EventDB) StoreLog(ctx context.Context, log types.Log, chainID uint32) error {
	ret := _m.Called(ctx, log, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, types.Log, uint32) error); ok {
		r0 = rf(ctx, log, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreReceipt provides a mock function with given fields: ctx, receipt, chainID
func (_m *EventDB) StoreReceipt(ctx context.Context, receipt types.Receipt, chainID uint32) error {
	ret := _m.Called(ctx, receipt, chainID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, types.Receipt, uint32) error); ok {
		r0 = rf(ctx, receipt, chainID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewEventDB interface {
	mock.TestingT
	Cleanup(func())
}

// NewEventDB creates a new instance of EventDB. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewEventDB(t mockConstructorTestingTNewEventDB) *EventDB {
	mock := &EventDB{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
