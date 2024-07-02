package quoter_test

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/mock"
	"github.com/synapsecns/sanguine/core/metrics"
	"github.com/synapsecns/sanguine/core/testsuite"
	fetcherMocks "github.com/synapsecns/sanguine/ethergo/submitter/mocks"
	submitterMocks "github.com/synapsecns/sanguine/ethergo/submitter/mocks"
	"github.com/synapsecns/sanguine/services/rfq/api/model"
	"github.com/synapsecns/sanguine/services/rfq/contracts/fastbridge"
	"github.com/synapsecns/sanguine/services/rfq/relayer/chain"
	inventoryMocks "github.com/synapsecns/sanguine/services/rfq/relayer/inventory/mocks"
	"github.com/synapsecns/sanguine/services/rfq/relayer/pricer"
	priceMocks "github.com/synapsecns/sanguine/services/rfq/relayer/pricer/mocks"
	"github.com/synapsecns/sanguine/services/rfq/relayer/quoter"
	"github.com/synapsecns/sanguine/services/rfq/relayer/reldb"
)

func (s *QuoterSuite) TestGenerateQuotes() {
	// Generate quotes for USDC on the destination chain.
	balance := big.NewInt(1000_000_000) // 1000 USDC
	quotes, err := s.manager.GenerateQuotes(s.GetTestContext(), int(s.destination), common.HexToAddress("0x0b2c639c533813f4aa9d7837caf62653d097ff85"), balance)
	s.Require().NoError(err)

	// Verify the quotes are generated as expected.
	expectedQuotes := []model.PutQuoteRequest{
		{
			OriginChainID:   int(s.origin),
			OriginTokenAddr: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			DestChainID:     int(s.destination),
			DestTokenAddr:   "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85",
			DestAmount:      balance.String(),
			MaxOriginAmount: balance.String(),
			FixedFee:        "100050000",
		},
	}
	s.Equal(expectedQuotes, quotes)
}

func (s *QuoterSuite) TestGenerateQuotesForNativeToken() {
	// Generate quotes for ETH on the destination chain.
	balance, _ := new(big.Int).SetString("1000000000000000000", 10) // 1 ETH
	quotes, err := s.manager.GenerateQuotes(s.GetTestContext(), int(s.destinationEth), chain.EthAddress, balance)
	s.Require().NoError(err)

	minGasToken, err := s.config.GetMinGasToken(int(s.destination))
	s.NoError(err)
	expectedQuoteAmount := new(big.Int).Sub(balance, minGasToken)

	// Verify the quotes are generated as expected.
	expectedQuotes := []model.PutQuoteRequest{
		{
			OriginChainID:   int(s.origin),
			OriginTokenAddr: chain.EthAddress.String(),
			DestChainID:     int(s.destinationEth),
			DestTokenAddr:   chain.EthAddress.String(),
			DestAmount:      expectedQuoteAmount.String(),
			MaxOriginAmount: expectedQuoteAmount.String(),
			FixedFee:        "150000000000000000", // (500k gas + 1m gas) * 100 gwei
		},
	}
	s.Equal(expectedQuotes, quotes)

	// Set MinGasToken and make sure it is accounted for in the DestAmount.
	s.config.BaseChainConfig.MinGasToken = "100000000000000000" // 0.1 ETH
	s.manager.SetConfig(s.config)

	quotes, err = s.manager.GenerateQuotes(s.GetTestContext(), int(s.destinationEth), chain.EthAddress, balance)
	s.Require().NoError(err)

	minGasToken, err = s.config.GetMinGasToken(int(s.destination))
	s.NoError(err)
	expectedQuoteAmount = new(big.Int).Sub(balance, minGasToken)

	// Verify the quotes are generated as expected.
	expectedQuotes = []model.PutQuoteRequest{
		{
			OriginChainID:   int(s.origin),
			OriginTokenAddr: chain.EthAddress.String(),
			DestChainID:     int(s.destinationEth),
			DestTokenAddr:   chain.EthAddress.String(),
			DestAmount:      expectedQuoteAmount.String(),
			MaxOriginAmount: expectedQuoteAmount.String(),
			FixedFee:        "150000000000000000", // (500k gas + 1m gas) * 100 gwei
		},
	}
	s.Equal(expectedQuotes, quotes)

	// Set MinGasToken to balance and make sure no quotes are generated.
	s.config.BaseChainConfig.MinGasToken = "1000000000000000001" // 0.1 ETH
	s.manager.SetConfig(s.config)

	quotes, err = s.manager.GenerateQuotes(s.GetTestContext(), int(s.destinationEth), chain.EthAddress, balance)
	s.NoError(err)
	s.Equal(quotes[0].DestAmount, "0")
	s.Equal(quotes[0].MaxOriginAmount, "0")
}

func (s *QuoterSuite) TestShouldProcess() {
	// Should process a valid quote.
	balance := big.NewInt(1000_000_000) // 1000 USDC
	fee := big.NewInt(100_050_000)      // 100.05 USDC
	quote := reldb.QuoteRequest{
		BlockNumber:         1,
		OriginTokenDecimals: 6,
		DestTokenDecimals:   6,
		Transaction: fastbridge.IFastBridgeBridgeTransaction{
			OriginChainId: s.origin,
			DestChainId:   s.destination,
			OriginToken:   common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
			DestToken:     common.HexToAddress("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
			OriginAmount:  balance,
			DestAmount:    new(big.Int).Sub(balance, fee),
		},
	}
	s.True(s.manager.ShouldProcess(s.GetTestContext(), quote))

	// Set different numbers of decimals for origin / dest tokens; should never process this.
	badQuote := quote
	badQuote.DestTokenDecimals = 18
	s.False(s.manager.ShouldProcess(s.GetTestContext(), badQuote))

	// Toggle relayPaused
	s.manager.SetRelayPaused(true)
	s.False(s.manager.ShouldProcess(s.GetTestContext(), quote))
	s.manager.SetRelayPaused(false)
	s.True(s.manager.ShouldProcess(s.GetTestContext(), quote))
}

func (s *QuoterSuite) TestIsProfitable() {
	// Set fee to breakeven; i.e. destAmount = originAmount - fee.
	balance := big.NewInt(1000_000_000) // 1000 USDC
	fee := big.NewInt(100_050_000)      // 100.05 USDC
	quote := reldb.QuoteRequest{
		BlockNumber:         1,
		OriginTokenDecimals: 6,
		DestTokenDecimals:   6,
		Transaction: fastbridge.IFastBridgeBridgeTransaction{
			OriginChainId: s.origin,
			DestChainId:   s.destination,
			OriginToken:   common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
			DestToken:     common.HexToAddress("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
			OriginAmount:  balance,
			DestAmount:    new(big.Int).Sub(balance, fee),
		},
	}
	s.True(s.manager.IsProfitable(s.GetTestContext(), quote))

	// Set fee to greater than breakeven; i.e. destAmount > originAmount - fee.
	quote.Transaction.DestAmount = new(big.Int).Sub(balance, new(big.Int).Mul(fee, big.NewInt(2)))
	s.True(s.manager.IsProfitable(s.GetTestContext(), quote))

	// Set fee to less than breakeven; i.e. destAmount < originAmount - fee.
	quote.Transaction.DestAmount = balance
	s.False(s.manager.IsProfitable(s.GetTestContext(), quote))
}

func (s *QuoterSuite) TestGetOriginAmount() {
	origin := int(s.origin)
	dest := int(s.destination)
	address := common.HexToAddress("0x0b2c639c533813f4aa9d7837caf62653d097ff85")
	balance := big.NewInt(1000_000_000) // 1000 USDC

	setQuoteParams := func(quotePct, quoteOffset float64, minQuoteAmount string) {
		s.config.BaseChainConfig.QuotePct = quotePct
		destTokenCfg := s.config.Chains[dest].Tokens["USDC"]
		destTokenCfg.MinQuoteAmount = minQuoteAmount
		originTokenCfg := s.config.Chains[origin].Tokens["USDC"]
		originTokenCfg.QuoteOffsetBps = quoteOffset
		s.config.Chains[dest].Tokens["USDC"] = destTokenCfg
		s.config.Chains[origin].Tokens["USDC"] = originTokenCfg
		s.manager.SetConfig(s.config)
	}

	// Set default quote params; should return the balance.
	quoteAmount, err := s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount := balance
	s.Equal(expectedAmount, quoteAmount)

	// Set QuotePct to 50 with MinQuoteAmount of 0; should be 50% of balance.
	setQuoteParams(50, 0, "0")
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(500_000_000)
	s.Equal(expectedAmount, quoteAmount)

	// Set QuotePct to 50 with QuoteOffset of -1%. Should be 1% less than 50% of balance.
	setQuoteParams(50, -100, "0")
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(495_000_000)
	s.Equal(expectedAmount, quoteAmount)

	// Set QuotePct to 25 with MinQuoteAmount of 500; should be 50% of balance.
	setQuoteParams(25, 0, "500")
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(500_000_000)
	s.Equal(expectedAmount, quoteAmount)

	// Set QuotePct to 25 with MinQuoteAmount of 500; should be 50% of balance.
	setQuoteParams(25, 0, "500")
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(500_000_000)
	s.Equal(expectedAmount, quoteAmount)

	// Set QuotePct to 25 with MinQuoteAmount of 1500; should be total balance.
	setQuoteParams(25, 0, "1500")
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(1000_000_000)
	s.Equal(expectedAmount, quoteAmount)

	// Set NumPendingTxes to 10, should return 0.
	s.setNumPendingTxes(10)
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(0)
	s.Equal(expectedAmount, quoteAmount)
	s.setNumPendingTxes(0)

	// Toggle insufficient gas; should be 0.
	s.setGasSufficiency(false)
	quoteAmount, err = s.manager.GetOriginAmount(s.GetTestContext(), origin, dest, address, balance)
	s.NoError(err)
	expectedAmount = big.NewInt(0)
	s.Equal(expectedAmount, quoteAmount)
}

func (s *QuoterSuite) setGasSufficiency(sufficient bool) {
	inventoryManager := new(inventoryMocks.Manager)
	inventoryManager.On(testsuite.GetFunctionName(inventoryManager.HasSufficientGas), mock.Anything, mock.Anything, mock.Anything).Return(sufficient, nil)
	s.setQuoter(inventoryManager, nil)
}

func (s *QuoterSuite) setNumPendingTxes(numPending int) {
	txSubmitter := new(submitterMocks.TransactionSubmitter)
	txSubmitter.On(testsuite.GetFunctionName(txSubmitter.GetNumPendingTxes), mock.Anything).Return(numPending)
	s.setQuoter(nil, txSubmitter)
}

func (s *QuoterSuite) setQuoter(im *inventoryMocks.Manager, ts *submitterMocks.TransactionSubmitter) {
	clientFetcher := new(fetcherMocks.ClientFetcher)
	priceFetcher := new(priceMocks.CoingeckoPriceFetcher)
	priceFetcher.On(testsuite.GetFunctionName(priceFetcher.GetPrice), mock.Anything, mock.Anything).Return(0., fmt.Errorf("not using mocked price"))
	feePricer := pricer.NewFeePricer(s.config, clientFetcher, priceFetcher, metrics.NewNullHandler())

	if im == nil {
		im = new(inventoryMocks.Manager)
		im.On(testsuite.GetFunctionName(im.HasSufficientGas), mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
	}
	if ts == nil {
		ts = new(submitterMocks.TransactionSubmitter)
		ts.On(testsuite.GetFunctionName(ts.GetNumPendingTxes), mock.Anything).Return(0)
	}

	mgr, err := quoter.NewQuoterManager(s.config, metrics.NewNullHandler(), im, nil, feePricer, nil, ts)
	s.NoError(err)

	var ok bool
	s.manager, ok = mgr.(*quoter.Manager)
	s.True(ok)

}

func (s *QuoterSuite) TestGetDestAmount() {
	balance := big.NewInt(1000_000_000) // 1000 USDC

	chainID := int(s.destination)
	setQuoteParams := func(quoteOffsetBps, quoteWidthBps float64) {
		s.config.BaseChainConfig.QuoteWidthBps = quoteWidthBps
		tokenCfg := s.config.Chains[chainID].Tokens["USDC"]
		tokenCfg.QuoteOffsetBps = quoteOffsetBps
		s.config.Chains[chainID].Tokens["USDC"] = tokenCfg
		s.manager.SetConfig(s.config)
	}

	// Set default quote params; should return the balance.
	destAmount, err := s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount := balance
	s.Equal(expectedAmount, destAmount)

	// Set QuoteWidthBps to 100, should return 99% of balance.
	setQuoteParams(0, 100)
	destAmount, err = s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount = big.NewInt(990_000_000)
	s.Equal(expectedAmount, destAmount)

	// Set QuoteWidthBps to 500, should return 95% of balance.
	setQuoteParams(0, 500)
	destAmount, err = s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount = big.NewInt(950_000_000)
	s.Equal(expectedAmount, destAmount)

	// Set QuoteWidthBps to 500 and QuoteOffsetBps to 100, should return 94% of balance.
	setQuoteParams(100, 500)
	destAmount, err = s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount = big.NewInt(940_000_000)
	s.Equal(expectedAmount, destAmount)

	// Set QuoteWidthBps to 500 and QuoteOffsetBps to -100, should return 96% of balance.
	setQuoteParams(-100, 500)
	destAmount, err = s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount = big.NewInt(960_000_000)
	s.Equal(expectedAmount, destAmount)

	// Set QuoteWidthBps to -100, should default to balance.
	setQuoteParams(0, -100)
	destAmount, err = s.manager.GetDestAmount(s.GetTestContext(), balance, chainID, "USDC")
	s.NoError(err)
	expectedAmount = balance
	s.Equal(expectedAmount, destAmount)
}
