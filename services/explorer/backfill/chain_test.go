package backfill_test

import (
	gosql "database/sql"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/core"
	"github.com/synapsecns/sanguine/services/explorer/backfill"
	"github.com/synapsecns/sanguine/services/explorer/config"
	"github.com/synapsecns/sanguine/services/explorer/consumer/fetcher"
	"github.com/synapsecns/sanguine/services/explorer/consumer/parser"
	parserpkg "github.com/synapsecns/sanguine/services/explorer/consumer/parser"
	"github.com/synapsecns/sanguine/services/explorer/db/sql"
	"github.com/synapsecns/sanguine/services/explorer/testutil/testcontracts"
	bridgeTypes "github.com/synapsecns/sanguine/services/explorer/types/bridge"
	swapTypes "github.com/synapsecns/sanguine/services/explorer/types/swap"
	"math/big"
)

func arrayToTokenIndexMap(input []*big.Int) map[uint8]string {
	output := map[uint8]string{}
	for i := range input {
		output[uint8(i)] = input[i].String()
	}
	return output
}

//nolint:maintidx
func (b *BackfillSuite) TestBackfill() {
	testChainID := b.testBackend.GetBigChainID()
	bridgeContract, bridgeRef := b.testDeployManager.GetTestSynapseBridge(b.GetTestContext(), b.testBackend)
	bridgeV1Contract, bridgeV1Ref := b.testDeployManager.GetTestSynapseBridgeV1(b.GetTestContext(), b.testBackend)
	swapContractA, swapRefA := b.testDeployManager.GetTestSwapFlashLoan(b.GetTestContext(), b.testBackend)
	messageBusContract, _ := b.testDeployManager.GetTestMessageBusUpgradeable(b.GetTestContext(), b.testBackend)

	testDeployManagerB := testcontracts.NewDeployManager(b.T())
	swapContractB, swapRefB := testDeployManagerB.GetTestSwapFlashLoan(b.GetTestContext(), b.testBackend)

	lastBlock := uint64(12)
	transactOpts := b.testBackend.GetTxContext(b.GetTestContext(), nil)

	// Initialize testing config.
	contractConfigBridge := config.ContractConfig{
		ContractType: "bridge",
		Address:      bridgeContract.Address().String(),
		StartBlock:   0,
	}
	contractConfigBridgeV1 := config.ContractConfig{
		ContractType: "bridge",
		Address:      bridgeV1Contract.Address().String(),
		StartBlock:   0,
	}
	contractConfigSwap1 := config.ContractConfig{
		ContractType: "swap",
		Address:      swapContractA.Address().String(),
		StartBlock:   0,
	}
	contractConfigSwap2 := config.ContractConfig{
		ContractType: "swap",
		Address:      swapContractB.Address().String(),
		StartBlock:   0,
	}
	contractMessageBus := config.ContractConfig{
		ContractType: "messagebus",
		Address:      messageBusContract.Address().String(),
		StartBlock:   0,
	}

	// Create the chain configs
	chainConfigs := []config.ChainConfig{
		{
			ChainID:             uint32(testChainID.Uint64()),
			RPCURL:              gofakeit.URL(),
			FetchBlockIncrement: 100,
			MaxGoroutines:       5,
			Contracts:           []config.ContractConfig{contractConfigBridge, contractConfigSwap1, contractConfigSwap2, contractMessageBus},
		},
	}
	chainConfigsV1 := []config.ChainConfig{
		{
			ChainID:             uint32(testChainID.Uint64()),
			RPCURL:              gofakeit.URL(),
			FetchBlockIncrement: 100,
			MaxGoroutines:       5,
			Contracts:           []config.ContractConfig{contractConfigBridgeV1, contractConfigSwap1, contractConfigSwap2, contractMessageBus},
		},
	}

	// Store blocktimes for testing defillama and timestamp indexing.
	for i := uint64(0); i < 13; i++ {
		err := b.eventDB.StoreBlockTime(b.GetTestContext(), uint32(testChainID.Uint64()), i, i)
		Nil(b.T(), err)
	}

	// Store every bridge event.
	bridgeTx, err := bridgeRef.TestDeposit(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(2)), 1)
	depositLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 2)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestRedeem(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(int64(gofakeit.Uint32()))), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(2)), 2)
	redeemLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 2)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestWithdraw(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), [32]byte{byte(gofakeit.Uint64())})
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(2)), 3)
	withdrawLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 2)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestMint(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), [32]byte{byte(gofakeit.Uint64())})
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(3)), 1)
	mintLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 3)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestDepositAndSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(6)), 1)
	depositAndSwapLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 6)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestRedeemAndSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(7)), 1)
	redeemAndSwapLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 7)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestRedeemAndRemove(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(8)), 1)
	redeemAndRemoveLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 8)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestMintAndSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), common.BigToAddress(big.NewInt(gofakeit.Int64())), gofakeit.Uint8(), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), [32]byte{byte(gofakeit.Uint64())})
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(9)), 1)
	mintAndSwapLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 9)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestWithdrawAndRemove(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), common.BigToAddress(big.NewInt(gofakeit.Int64())), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), [32]byte{byte(gofakeit.Uint64())})
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(10)), 1)
	withdrawAndRemoveLog, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 10)
	Nil(b.T(), err)

	bridgeTx, err = bridgeRef.TestRedeemV2(transactOpts.TransactOpts, [32]byte{byte(gofakeit.Uint64())}, big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(11)), 1)
	redeemV2Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 12)
	Nil(b.T(), err)

	// Store every bridge event using the V1 contract.
	bridgeTx, err = bridgeV1Ref.TestDeposit(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	fmt.Println("hoshh", bridgeTx.Hash().String())
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(3)), 1)
	depositV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 3)
	Nil(b.T(), err)

	bridgeTx, err = bridgeV1Ref.TestRedeem(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(int64(gofakeit.Uint32()))), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(3)), 2)
	redeemV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 3)
	Nil(b.T(), err)

	bridgeTx, err = bridgeV1Ref.TestWithdraw(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())), [32]byte{byte(gofakeit.Uint64())})
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(3)), 3)
	withdrawV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 3)
	Nil(b.T(), err)

	bridgeTx, err = bridgeV1Ref.TestDepositAndSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(7)), 1)
	depositAndSwapV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 7)
	Nil(b.T(), err)

	bridgeTx, err = bridgeV1Ref.TestRedeemAndSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(8)), 1)
	redeemAndSwapV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 8)
	Nil(b.T(), err)

	bridgeTx, err = bridgeV1Ref.TestRedeemAndRemove(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint32())), common.HexToAddress(testTokens[0].TokenAddress), big.NewInt(int64(gofakeit.Uint32())), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint32())), big.NewInt(int64(gofakeit.Uint32())))
	Nil(b.T(), err)
	b.storeEthTx(bridgeTx, testChainID, big.NewInt(int64(9)), 1)
	redeemAndRemoveV1Log, err := b.storeTestLog(bridgeTx, uint32(testChainID.Uint64()), 9)
	Nil(b.T(), err)

	// Store every swap event across two different swap contracts.
	swapTx, err := swapRefA.TestSwap(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(4)), 1)
	swapLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 4)
	Nil(b.T(), err)

	swapTx, err = swapRefB.TestAddLiquidity(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), []*big.Int{big.NewInt(int64(gofakeit.Uint64()))}, []*big.Int{big.NewInt(int64(gofakeit.Uint64()))}, big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(4)), 2)
	addLiquidityLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 4)
	Nil(b.T(), err)

	swapTx, err = swapRefB.TestRemoveLiquidity(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), []*big.Int{big.NewInt(int64(gofakeit.Uint64()))}, big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(4)), 3)
	removeLiquidityLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 4)
	Nil(b.T(), err)

	swapTx, err = swapRefA.TestRemoveLiquidityOne(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(5)), 1)
	removeLiquidityOneLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 5)
	Nil(b.T(), err)

	swapTx, err = swapRefA.TestRemoveLiquidityImbalance(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), []*big.Int{big.NewInt(int64(gofakeit.Uint64()))}, []*big.Int{big.NewInt(int64(gofakeit.Uint64()))}, big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(5)), 2)
	removeLiquidityImbalanceLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 5)
	Nil(b.T(), err)

	swapTx, err = swapRefB.TestNewAdminFee(transactOpts.TransactOpts, big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(6)), 1)
	newAdminFeeLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 6)
	Nil(b.T(), err)

	swapTx, err = swapRefA.TestNewSwapFee(transactOpts.TransactOpts, big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(7)), 1)
	newSwapFeeLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 7)
	Nil(b.T(), err)

	swapTx, err = swapRefA.TestRampA(transactOpts.TransactOpts, big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(8)), 1)
	rampALog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 8)
	Nil(b.T(), err)

	swapTx, err = swapRefB.TestStopRampA(transactOpts.TransactOpts, big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(8)), 1)
	stopRampALog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 8)
	Nil(b.T(), err)

	swapTx, err = swapRefA.TestFlashLoan(transactOpts.TransactOpts, common.BigToAddress(big.NewInt(gofakeit.Int64())), gofakeit.Uint8(), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())), big.NewInt(int64(gofakeit.Uint64())))
	Nil(b.T(), err)
	b.storeEthTx(swapTx, testChainID, big.NewInt(int64(12)), 1)
	flashLoanLog, err := b.storeTestLog(swapTx, uint32(testChainID.Uint64()), 12)
	Nil(b.T(), err)

	// Go through each contract and save the end height in scribe
	for i := range chainConfigs[0].Contracts {
		//  the last block store per contract
		err = b.eventDB.StoreLastIndexed(b.GetTestContext(), common.HexToAddress(chainConfigs[0].Contracts[i].Address), uint32(testChainID.Uint64()), lastBlock)
		Nil(b.T(), err)
	}
	for i := range chainConfigsV1[0].Contracts {
		//  the last block store per contract
		err = b.eventDB.StoreLastIndexed(b.GetTestContext(), common.HexToAddress(chainConfigsV1[0].Contracts[i].Address), uint32(testChainID.Uint64()), lastBlock)
		Nil(b.T(), err)
	}

	// Set up a ChainBackfiller
	bcf, err := fetcher.NewBridgeConfigFetcher(b.bridgeConfigContract.Address(), b.bridgeConfigContract)
	Nil(b.T(), err)
	bp, err := parser.NewBridgeParser(b.db, bridgeContract.Address(), *bcf, b.consumerFetcher)
	Nil(b.T(), err)
	bpv1, err := parser.NewBridgeParser(b.db, bridgeV1Contract.Address(), *bcf, b.consumerFetcher)
	Nil(b.T(), err)

	// srB is the swap ref for getting token data
	srA, err := fetcher.NewSwapFetcher(swapContractA.Address(), b.testBackend)
	Nil(b.T(), err)
	spA, err := parser.NewSwapParser(b.db, swapContractA.Address(), *srA, b.consumerFetcher)
	Nil(b.T(), err)

	// srB is the swap ref for getting token data
	srB, err := fetcher.NewSwapFetcher(swapContractB.Address(), b.testBackend)
	Nil(b.T(), err)
	spB, err := parser.NewSwapParser(b.db, swapContractB.Address(), *srB, b.consumerFetcher)
	Nil(b.T(), err)
	spMap := map[common.Address]*parser.SwapParser{}
	spMap[swapContractA.Address()] = spA
	spMap[swapContractB.Address()] = spB
	f := fetcher.NewFetcher(b.gqlClient)

	// Set up message bus parser
	mbp, err := parser.NewMessageBusParser(b.db, messageBusContract.Address(), b.consumerFetcher)
	Nil(b.T(), err)

	// Test the first chain in the config file
	chainBackfiller := backfill.NewChainBackfiller(b.db, bp, spMap, mbp, *f, chainConfigs[0])
	chainBackfillerV1 := backfill.NewChainBackfiller(b.db, bpv1, spMap, mbp, *f, chainConfigsV1[0])

	// Backfill the blocks
	// TODO: store the latest block number to query to in scribe db
	var count int64
	err = chainBackfiller.Backfill(b.GetTestContext())
	Nil(b.T(), err)
	swapEvents := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Find(&sql.SwapEvent{}).Count(&count)
	Nil(b.T(), swapEvents.Error)
	Equal(b.T(), int64(10), count)
	bridgeEvents := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Find(&sql.BridgeEvent{}).Count(&count)
	Nil(b.T(), bridgeEvents.Error)
	Equal(b.T(), int64(10), count)

	// Test bridge parity
	err = b.depositParity(depositLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.redeemParity(redeemLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.withdrawParity(withdrawLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.mintParity(mintLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.depositAndSwapParity(depositAndSwapLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.redeemAndSwapParity(redeemAndSwapLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.redeemAndRemoveParity(redeemAndRemoveLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.mintAndSwapParity(mintAndSwapLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.withdrawAndRemoveParity(withdrawAndRemoveLog, bp, uint32(testChainID.Uint64()), false)
	Nil(b.T(), err)
	err = b.redeemV2Parity(redeemV2Log, bp, uint32(testChainID.Uint64()))
	Nil(b.T(), err)

	// Test swap parity
	err = b.swapParity(swapLog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.addLiquidityParity(addLiquidityLog, spB, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.removeLiquidityParity(removeLiquidityLog, spB, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.removeLiquidityOneParity(removeLiquidityOneLog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.removeLiquidityImbalanceParity(removeLiquidityImbalanceLog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.newAdminFeeParity(newAdminFeeLog, spB, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.newSwapFeeParity(newSwapFeeLog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.rampAParity(rampALog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.stopRampAParity(stopRampALog, spB, uint32(testChainID.Uint64()))
	Nil(b.T(), err)
	err = b.flashLoanParity(flashLoanLog, spA, uint32(testChainID.Uint64()))
	Nil(b.T(), err)

	// Test bridge v1 parity
	err = chainBackfillerV1.Backfill(b.GetTestContext())
	Nil(b.T(), err)

	err = b.depositParity(depositV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)
	err = b.redeemParity(redeemV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)
	err = b.withdrawParity(withdrawV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)
	err = b.depositAndSwapParity(depositAndSwapV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)
	err = b.redeemAndSwapParity(redeemAndSwapV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)
	err = b.redeemAndRemoveParity(redeemAndRemoveV1Log, bpv1, uint32(testChainID.Uint64()), true)
	Nil(b.T(), err)

	bridgeEvents = b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Find(&sql.BridgeEvent{}).Count(&count)
	Nil(b.T(), bridgeEvents.Error)
	Equal(b.T(), int64(16), count)

	lastBlockStored, err := b.db.GetUint64(b.GetTestContext(), fmt.Sprintf(
		"SELECT ifNull(%s, 0) FROM last_blocks WHERE %s = %d",
		sql.BlockNumberFieldName, sql.ChainIDFieldName, testChainID.Uint64(),
	))

	Nil(b.T(), err)
	Equal(b.T(), lastBlock, lastBlockStored)
}

// storeTestLogs stores the test logs in the database.
func (b *BackfillSuite) storeTestLog(tx *types.Transaction, chainID uint32, blockNumber uint64) (*types.Log, error) {
	b.testBackend.WaitForConfirmation(b.GetTestContext(), tx)
	receipt, err := b.testBackend.TransactionReceipt(b.GetTestContext(), tx.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get receipt for transaction %s: %w", tx.Hash().String(), err)
	}
	receipt.Logs[0].BlockNumber = blockNumber
	err = b.eventDB.StoreLog(b.GetTestContext(), *receipt.Logs[0], chainID)
	if err != nil {
		return nil, fmt.Errorf("error storing swap log: %w", err)
	}
	return receipt.Logs[0], nil
}

//nolint:dupl
func (b *BackfillSuite) depositParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.FiltererV1.ParseTokenDeposit(*log)
		_ = parsedLog
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.DepositEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:          recipient,
				DestinationChainID: parsedLog.ChainId,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenDeposit(*log)
	_ = parsedLog
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.DepositEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:          recipient,
			DestinationChainID: parsedLog.ChainId,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) redeemParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.FiltererV1.ParseTokenRedeem(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.RedeemEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:          recipient,
				DestinationChainID: parsedLog.ChainId,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenRedeem(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.RedeemEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:          recipient,
			DestinationChainID: parsedLog.ChainId,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) withdrawParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.FiltererV1.ParseTokenWithdraw(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		kappa := gosql.NullString{
			String: common.Bytes2Hex(parsedLog.Kappa[:]),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.WithdrawEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient: recipient,
				Fee:       parsedLog.Fee,
				Kappa:     kappa,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenWithdraw(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	kappa := gosql.NullString{
		String: common.Bytes2Hex(parsedLog.Kappa[:]),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.WithdrawEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient: recipient,
			Fee:       parsedLog.Fee,
			Kappa:     kappa,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) mintParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenMint(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		kappa := gosql.NullString{
			String: common.Bytes2Hex(parsedLog.Kappa[:]),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.MintEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient: recipient,
				Fee:       parsedLog.Fee,
				Kappa:     kappa,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenMint(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	kappa := gosql.NullString{
		String: common.Bytes2Hex(parsedLog.Kappa[:]),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.MintEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient: recipient,
			Fee:       parsedLog.Fee,
			Kappa:     kappa,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) depositAndSwapParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenDepositAndSwap(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.DepositAndSwapEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:      recipient,
				TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
				TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
				MinDy:          parsedLog.MinDy,
				Deadline:       parsedLog.Deadline,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenDepositAndSwap(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.DepositAndSwapEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:      recipient,
			TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
			TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
			MinDy:          parsedLog.MinDy,
			Deadline:       parsedLog.Deadline,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) redeemAndSwapParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenRedeemAndSwap(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.RedeemAndSwapEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:      recipient,
				TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
				TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
				MinDy:          parsedLog.MinDy,
				Deadline:       parsedLog.Deadline,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenRedeemAndSwap(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.RedeemAndSwapEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:      recipient,
			TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
			TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
			MinDy:          parsedLog.MinDy,
			Deadline:       parsedLog.Deadline,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) redeemAndRemoveParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenRedeemAndRemove(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.RedeemAndRemoveEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:      recipient,
				SwapTokenIndex: big.NewInt(int64(parsedLog.SwapTokenIndex)),
				SwapMinAmount:  parsedLog.SwapMinAmount,
				SwapDeadline:   parsedLog.SwapDeadline,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenRedeemAndRemove(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.RedeemAndRemoveEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:      recipient,
			SwapTokenIndex: big.NewInt(int64(parsedLog.SwapTokenIndex)),
			SwapMinAmount:  parsedLog.SwapMinAmount,
			SwapDeadline:   parsedLog.SwapDeadline,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) mintAndSwapParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenMintAndSwap(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		kappa := gosql.NullString{
			String: common.Bytes2Hex(parsedLog.Kappa[:]),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.MintAndSwapEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:      recipient,
				Fee:            parsedLog.Fee,
				TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
				TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
				MinDy:          parsedLog.MinDy,
				Deadline:       parsedLog.Deadline,
				SwapSuccess:    big.NewInt(int64(*parserpkg.BoolToUint8(&parsedLog.SwapSuccess))),
				Kappa:          kappa,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenMintAndSwap(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	kappa := gosql.NullString{
		String: common.Bytes2Hex(parsedLog.Kappa[:]),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.MintAndSwapEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:      recipient,
			Fee:            parsedLog.Fee,
			TokenIndexFrom: big.NewInt(int64(parsedLog.TokenIndexFrom)),
			TokenIndexTo:   big.NewInt(int64(parsedLog.TokenIndexTo)),
			MinDy:          parsedLog.MinDy,
			Deadline:       parsedLog.Deadline,
			SwapSuccess:    big.NewInt(int64(*parserpkg.BoolToUint8(&parsedLog.SwapSuccess))),
			Kappa:          kappa,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) withdrawAndRemoveParity(log *types.Log, parser *parser.BridgeParser, chainID uint32, useV1 bool) error {
	// parse the log
	if useV1 {
		parsedLog, err := parser.Filterer.ParseTokenWithdrawAndRemove(*log)
		if err != nil {
			return fmt.Errorf("error parsing log: %w", err)
		}
		recipient := gosql.NullString{
			String: parsedLog.To.String(),
			Valid:  true,
		}
		kappa := gosql.NullString{
			String: common.Bytes2Hex(parsedLog.Kappa[:]),
			Valid:  true,
		}
		var count int64
		events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
			Where(&sql.BridgeEvent{
				ContractAddress: log.Address.String(),
				ChainID:         chainID,
				EventType:       bridgeTypes.WithdrawAndRemoveEvent.Int(),
				BlockNumber:     log.BlockNumber,
				TxHash:          log.TxHash.String(),
				Token:           parsedLog.Token.String(),
				Amount:          parsedLog.Amount,

				Recipient:      recipient,
				SwapTokenIndex: big.NewInt(int64(parsedLog.SwapTokenIndex)),
				SwapMinAmount:  parsedLog.SwapMinAmount,
				SwapDeadline:   parsedLog.SwapDeadline,
				SwapSuccess:    big.NewInt(int64(*parserpkg.BoolToUint8(&parsedLog.SwapSuccess))),
				Kappa:          kappa,
			}).Count(&count)
		if events.Error != nil {
			return fmt.Errorf("error querying for event: %w", events.Error)
		}
		Equal(b.T(), int64(1), count)
		return nil
	}
	parsedLog, err := parser.Filterer.ParseTokenWithdrawAndRemove(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipient := gosql.NullString{
		String: parsedLog.To.String(),
		Valid:  true,
	}
	kappa := gosql.NullString{
		String: common.Bytes2Hex(parsedLog.Kappa[:]),
		Valid:  true,
	}
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.WithdrawAndRemoveEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			Recipient:      recipient,
			SwapTokenIndex: big.NewInt(int64(parsedLog.SwapTokenIndex)),
			SwapMinAmount:  parsedLog.SwapMinAmount,
			SwapDeadline:   parsedLog.SwapDeadline,
			SwapSuccess:    big.NewInt(int64(*parserpkg.BoolToUint8(&parsedLog.SwapSuccess))),
			Kappa:          kappa,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) redeemV2Parity(log *types.Log, parser *parser.BridgeParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseTokenRedeemV2(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	recipientBytes := gosql.NullString{
		String: common.Bytes2Hex(parsedLog.To[:]),
		Valid:  true,
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.BridgeEvent{}).
		Where(&sql.BridgeEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       bridgeTypes.RedeemV2Event.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),
			Token:           parsedLog.Token.String(),
			Amount:          parsedLog.Amount,

			RecipientBytes:     recipientBytes,
			DestinationChainID: parsedLog.ChainId,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) swapParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log

	parsedLog, err := parser.Filterer.ParseTokenSwap(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	buyer := gosql.NullString{
		String: parsedLog.Buyer.String(),
		Valid:  true,
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.TokenSwapEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Buyer:        buyer,
			TokensSold:   parsedLog.TokensSold,
			TokensBought: parsedLog.TokensBought,
			SoldID:       parsedLog.SoldId,
			BoughtID:     parsedLog.BoughtId,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) addLiquidityParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseAddLiquidity(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	provider := gosql.NullString{
		String: parsedLog.Provider.String(),
		Valid:  true,
	}
	var storedLog sql.SwapEvent
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.AddLiquidityEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Provider:      provider,
			Invariant:     parsedLog.Invariant,
			LPTokenSupply: parsedLog.LpTokenSupply,
		}).
		Find(&storedLog).
		Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	Equal(b.T(), arrayToTokenIndexMap(parsedLog.TokenAmounts), storedLog.Amount)
	Equal(b.T(), arrayToTokenIndexMap(parsedLog.Fees), storedLog.AmountFee)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) removeLiquidityParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseRemoveLiquidity(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	provider := gosql.NullString{
		String: parsedLog.Provider.String(),
		Valid:  true,
	}

	arrayToTokenIndexMap(parsedLog.TokenAmounts)

	var storedLog sql.SwapEvent
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.RemoveLiquidityEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Provider:      provider,
			LPTokenSupply: parsedLog.LpTokenSupply,
		}).
		Find(&storedLog).
		Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	Equal(b.T(), arrayToTokenIndexMap(parsedLog.TokenAmounts), storedLog.Amount)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) removeLiquidityOneParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseRemoveLiquidityOne(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	provider := gosql.NullString{
		String: parsedLog.Provider.String(),
		Valid:  true,
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.RemoveLiquidityOneEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Provider:      provider,
			LPTokenAmount: parsedLog.LpTokenAmount,
			LPTokenSupply: parsedLog.LpTokenSupply,
			BoughtID:      parsedLog.BoughtId,
			TokensBought:  parsedLog.TokensBought,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) removeLiquidityImbalanceParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseRemoveLiquidityImbalance(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}
	provider := gosql.NullString{
		String: parsedLog.Provider.String(),
		Valid:  true,
	}
	var storedLog sql.SwapEvent
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.RemoveLiquidityImbalanceEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Provider:      provider,
			Invariant:     parsedLog.Invariant,
			LPTokenSupply: parsedLog.LpTokenSupply,
		}).
		Find(&storedLog).
		Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	Equal(b.T(), arrayToTokenIndexMap(parsedLog.TokenAmounts), storedLog.Amount)
	Equal(b.T(), arrayToTokenIndexMap(parsedLog.Fees), storedLog.AmountFee)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) newAdminFeeParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseNewAdminFee(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.NewAdminFeeEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			NewAdminFee: parsedLog.NewAdminFee,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) newSwapFeeParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseNewSwapFee(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.NewSwapFeeEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			NewSwapFee: parsedLog.NewSwapFee,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) rampAParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseRampA(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.RampAEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			OldA:        parsedLog.OldA,
			NewA:        parsedLog.NewA,
			InitialTime: parsedLog.InitialTime,
			FutureTime:  parsedLog.FutureTime,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) stopRampAParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseStopRampA(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}

	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.StopRampAEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			CurrentA: parsedLog.CurrentA,
			Time:     parsedLog.Time,
		}).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	return nil
}

//nolint:dupl
func (b *BackfillSuite) flashLoanParity(log *types.Log, parser *parser.SwapParser, chainID uint32) error {
	// parse the log
	parsedLog, err := parser.Filterer.ParseFlashLoan(*log)
	if err != nil {
		return fmt.Errorf("error parsing log: %w", err)
	}

	receiver := gosql.NullString{
		String: parsedLog.Receiver.String(),
		Valid:  true,
	}
	amountArray := map[uint8]string{parsedLog.TokenIndex: core.CopyBigInt(parsedLog.Amount).String()}
	feeArray := map[uint8]string{parsedLog.TokenIndex: core.CopyBigInt(parsedLog.AmountFee).String()}
	var storedLog sql.SwapEvent
	var count int64
	events := b.db.UNSAFE_DB().WithContext(b.GetTestContext()).Model(&sql.SwapEvent{}).
		Where(&sql.SwapEvent{
			ContractAddress: log.Address.String(),
			ChainID:         chainID,
			EventType:       swapTypes.FlashLoanEvent.Int(),
			BlockNumber:     log.BlockNumber,
			TxHash:          log.TxHash.String(),

			Receiver:    receiver,
			ProtocolFee: parsedLog.ProtocolFee,
		}).
		Find(&storedLog).Count(&count)
	if events.Error != nil {
		return fmt.Errorf("error querying for event: %w", events.Error)
	}
	Equal(b.T(), int64(1), count)
	Equal(b.T(), amountArray, storedLog.Amount)
	Equal(b.T(), feeArray, storedLog.AmountFee)
	return nil
}

// storeEthTx stores the eth transaction so the get sender functionality can be tested.
func (b *BackfillSuite) storeEthTx(tx *types.Transaction, chainID *big.Int, blockNumber *big.Int, index int) {
	err := b.eventDB.StoreEthTx(b.GetTestContext(), tx, uint32(chainID.Uint64()), common.BigToHash(blockNumber), blockNumber.Uint64(), uint64(index))
	Nil(b.T(), err)
}
