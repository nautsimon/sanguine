package db_test

import (
	"math/big"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/services/scribe/db"
)

func (t *DBSuite) TestStoreRetrieveReceipt() {
	t.RunOnAllDBs(func(testDB db.EventDB) {
		txHashRandom := gofakeit.Int64()
		chainID := gofakeit.Uint32()
		txHashA := common.BigToHash(big.NewInt(txHashRandom))
		txHashB := common.BigToHash(big.NewInt(txHashRandom + 1))
		randomLogsA := []types.Log{
			t.MakeRandomLog(txHashA),
			t.MakeRandomLog(txHashA),
		}
		randomLogsA[0].BlockNumber = 1
		randomLogsA[1].BlockNumber = 2
		randomLogsB := []types.Log{
			t.MakeRandomLog(txHashB),
			t.MakeRandomLog(txHashB),
		}
		randomLogsB[0].BlockNumber = 3
		randomLogsB[1].BlockNumber = 4

		// Store all random logs, since `RetrieveReceipt` needs to query them to build the Receipt.
		for _, log := range randomLogsA {
			err := testDB.StoreLog(t.GetTestContext(), log, chainID)
			Nil(t.T(), err)
		}
		for _, log := range randomLogsB {
			err := testDB.StoreLog(t.GetTestContext(), log, chainID+1)
			Nil(t.T(), err)
		}

		// Store two receipts with different tx hashes.
		receiptA := types.Receipt{
			Type:              gofakeit.Uint8(),
			PostState:         []byte(gofakeit.Sentence(10)),
			Status:            gofakeit.Uint64(),
			CumulativeGasUsed: gofakeit.Uint64(),
			Bloom:             types.BytesToBloom([]byte(gofakeit.Sentence(10))),
			Logs: []*types.Log{
				&randomLogsA[0],
				&randomLogsA[1],
			},
			TxHash:           txHashA,
			ContractAddress:  common.BigToAddress(big.NewInt(gofakeit.Int64())),
			GasUsed:          gofakeit.Uint64(),
			BlockNumber:      big.NewInt(1),
			TransactionIndex: uint(gofakeit.Uint64()),
		}
		err := testDB.StoreReceipt(t.GetTestContext(), receiptA, chainID)
		Nil(t.T(), err)

		receiptB := types.Receipt{
			Type:              gofakeit.Uint8(),
			PostState:         []byte(gofakeit.Sentence(10)),
			Status:            gofakeit.Uint64(),
			CumulativeGasUsed: gofakeit.Uint64(),
			Bloom:             types.BytesToBloom([]byte(gofakeit.Sentence(10))),
			Logs: []*types.Log{
				&randomLogsB[0],
				&randomLogsB[1],
			},
			TxHash:           txHashB,
			ContractAddress:  common.BigToAddress(big.NewInt(gofakeit.Int64())),
			GasUsed:          gofakeit.Uint64(),
			BlockNumber:      big.NewInt(2),
			TransactionIndex: uint(gofakeit.Uint64()),
		}
		err = testDB.StoreReceipt(t.GetTestContext(), receiptB, chainID+1)
		Nil(t.T(), err)

		// Ensure the receipts from the database match the ones stored.
		receiptFilter := db.ReceiptFilter{
			TxHash:  txHashA.String(),
			ChainID: chainID,
		}
		retrievedReceiptA, err := testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), receiptFilter, 1)
		Nil(t.T(), err)

		resA, err := receiptA.MarshalJSON()
		Nil(t.T(), err)
		resB, err := retrievedReceiptA[0].MarshalJSON()
		Nil(t.T(), err)
		Equal(t.T(), resA, resB)

		receiptFilter = db.ReceiptFilter{
			TxHash:  txHashB.String(),
			ChainID: chainID + 1,
		}
		retrievedReceiptB, err := testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), receiptFilter, 1)
		Nil(t.T(), err)

		resA, err = receiptB.MarshalJSON()
		Nil(t.T(), err)
		resB, err = retrievedReceiptB[0].MarshalJSON()
		Nil(t.T(), err)
		Equal(t.T(), resA, resB)

		// Ensure RetrieveAllReceipts gets all receipts.
		allReceipts, err := testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), db.ReceiptFilter{}, 1)
		Nil(t.T(), err)
		Equal(t.T(), 2, len(allReceipts))
	})
}

func (t *DBSuite) TestConfirmReceiptsInRange() {
	t.RunOnAllDBs(func(testDB db.EventDB) {
		chainID := gofakeit.Uint32()

		// Store five receipts.
		for i := 0; i < 5; i++ {
			receipt := t.MakeRandomReceipt(common.BigToHash(big.NewInt(gofakeit.Int64())))
			receipt.BlockNumber = big.NewInt(int64(i))
			err := testDB.StoreReceipt(t.GetTestContext(), receipt, chainID)
			Nil(t.T(), err)
		}

		// Confirm the first two receipts.
		err := testDB.ConfirmReceiptsInRange(t.GetTestContext(), 0, 1, chainID)
		Nil(t.T(), err)

		// Ensure the first two receipts are confirmed.
		receiptFilter := db.ReceiptFilter{
			ChainID:   chainID,
			Confirmed: true,
		}
		retrievedReceipts, err := testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), receiptFilter, 1)
		Nil(t.T(), err)
		Equal(t.T(), 2, len(retrievedReceipts))
		Equal(t.T(), retrievedReceipts[0].BlockNumber, big.NewInt(0))
		Equal(t.T(), retrievedReceipts[1].BlockNumber, big.NewInt(1))
	})
}

func (t *DBSuite) TestDeleteReceiptsForBlockHash() {
	t.RunOnAllDBs(func(testDB db.EventDB) {
		chainID := gofakeit.Uint32()

		// Store a receipt.
		receipt := t.MakeRandomReceipt(common.BigToHash(big.NewInt(gofakeit.Int64())))
		receipt.BlockHash = common.BigToHash(big.NewInt(5))
		err := testDB.StoreReceipt(t.GetTestContext(), receipt, chainID)
		Nil(t.T(), err)

		// Ensure the receipt is in the database.
		receiptFilter := db.ReceiptFilter{
			ChainID:   chainID,
			BlockHash: receipt.BlockHash.String(),
		}
		retrievedReceipts, err := testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), receiptFilter, 1)
		Nil(t.T(), err)
		Equal(t.T(), 1, len(retrievedReceipts))

		// Delete the receipt.
		err = testDB.DeleteReceiptsForBlockHash(t.GetTestContext(), receipt.BlockHash, chainID)
		Nil(t.T(), err)

		// Ensure the receipt is not in the database.
		retrievedReceipts, err = testDB.RetrieveReceiptsWithFilter(t.GetTestContext(), receiptFilter, 1)
		Nil(t.T(), err)
		Equal(t.T(), 0, len(retrievedReceipts))
	})
}

func (t *DBSuite) MakeRandomReceipt(txHash common.Hash) types.Receipt {
	return types.Receipt{
		Type:              gofakeit.Uint8(),
		PostState:         []byte(gofakeit.Sentence(10)),
		Status:            gofakeit.Uint64(),
		CumulativeGasUsed: gofakeit.Uint64(),
		Bloom:             types.BytesToBloom([]byte(gofakeit.Sentence(10))),
		Logs:              []*types.Log{},
		TxHash:            txHash,
		ContractAddress:   common.BigToAddress(big.NewInt(gofakeit.Int64())),
		GasUsed:           gofakeit.Uint64(),
		BlockNumber:       big.NewInt(int64(gofakeit.Uint32())),
		TransactionIndex:  uint(gofakeit.Uint64()),
	}
}
