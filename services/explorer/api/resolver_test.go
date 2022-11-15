package api_test

import (
	gosql "database/sql"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/services/explorer/db/sql"
	"github.com/synapsecns/sanguine/services/explorer/graphql/server/graph/model"
	"math"
	"math/big"
	"sort"
	"time"
)

//nolint:cyclop
func (g APISuite) TestAddressRanking() {
	var chainID uint32
	chainIDs := []uint32{g.chainIDs[0], g.chainIDs[1], g.chainIDs[2]}
	destinationChainIDA := g.chainIDs[3]
	destinationChainIDB := g.chainIDs[4]

	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))

	// used for validation later
	var addressesTried = make(map[string]int)

	// this counter lets us have a random variation in address occurrence
	resetTokenAddrCounter := gofakeit.Number(1, 3)
	// random token addr
	tokenAddr := common.BigToAddress(big.NewInt(gofakeit.Int64())).String()
	// for holding the current token addr in line the gofakeit.Bool() decides to pass true
	lastTokenAddr := tokenAddr
	// Generate bridge events for different chain IDs.
	for blockNumber := uint64(1); blockNumber <= 10; blockNumber++ {
		var destinationChainID uint32
		if blockNumber%2 == 0 {
			destinationChainID = destinationChainIDA
		} else {
			destinationChainID = destinationChainIDB
		}

		// if the token counter is zero reset it
		if resetTokenAddrCounter == 0 {
			tokenAddr = common.BigToAddress(big.NewInt(gofakeit.Int64())).String()
			lastTokenAddr = tokenAddr
			resetTokenAddrCounter = gofakeit.Number(1, 3)
		} else {
			// before using the current token addr, let throw in some randomness
			if gofakeit.Bool() {
				tokenAddr = common.BigToAddress(big.NewInt(gofakeit.Int64())).String()
			} else {
				resetTokenAddrCounter--
			}
		}

		currentTime := uint64(time.Now().Unix())

		// change up chainID (1/3 chance of using a new chain)
		chainID = chainIDs[gofakeit.Number(0, 2)]
		txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainID,
			Recipient:          gosql.NullString{String: address.String(), Valid: true},
			DestinationChainID: big.NewInt(int64(destinationChainID)),
			BlockNumber:        blockNumber,
			TxHash:             txHash.String(),
			EventIndex:         gofakeit.Uint64(),
			Token:              tokenAddr,
			TimeStamp:          &currentTime,
		})

		// add the tokenAddr inserted to the test map (for validation later)
		addressesTried[tokenAddr]++

		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDs[0], blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDs[1], blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDs[2], blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDA, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDB, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)

		// if a random address was inserted, revert to address corresponding to resetTokenAddrCounter
		if lastTokenAddr != tokenAddr {
			tokenAddr = lastTokenAddr
		}
	}

	blockNumberInit := uint64(10)
	err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, blockNumberInit, uint64(time.Now().Unix())*blockNumberInit)
	Nil(g.T(), err)

	result, err := g.client.GetAddressRanking(g.GetTestContext(), nil)
	Nil(g.T(), err)
	NotNil(g.T(), result)

	// check if the length of the response is same to the number of unique addresses inserted into test db
	Equal(g.T(), len(addressesTried), len(result.Response))

	// Validate contents of response by comparing to addressesTried
	for k, v := range addressesTried {
		for _, res := range result.Response {
			if *res.Address == k {
				Equal(g.T(), v, *res.Count)
			}
		}
	}
}

// nolint:cyclop
func (g APISuite) TestBridgeAmountStatistic() {
	chainID := g.chainIDs[0]
	destinationChainIDA := g.chainIDs[1]
	destinationChainIDB := g.chainIDs[2]
	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	tokenAddr := common.BigToAddress(big.NewInt(gofakeit.Int64())).String()

	cumulativePrice := []float64{}
	// Generate bridge events for different chain IDs.
	for blockNumber := uint64(1); blockNumber <= 10; blockNumber++ {
		var destinationChainID uint32
		if blockNumber%2 == 0 {
			destinationChainID = destinationChainIDA
		} else {
			destinationChainID = destinationChainIDB
		}

		currentTime := uint64(time.Now().Unix())
		price := float64(gofakeit.Number(1, 300))
		cumulativePrice = append(cumulativePrice, price)
		txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainID,
			Recipient:          gosql.NullString{String: address.String(), Valid: true},
			DestinationChainID: big.NewInt(int64(destinationChainID)),
			BlockNumber:        blockNumber,
			TxHash:             txHash.String(),
			EventIndex:         gofakeit.Uint64(),
			Token:              tokenAddr,
			Amount:             big.NewInt(int64(gofakeit.Number(1, 300))),
			AmountUSD:          &price,
			TimeStamp:          &currentTime,
		})
		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDA, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDB, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
	}

	total := 0.0
	for _, v := range cumulativePrice {
		total += v
	}
	count := float64(len(cumulativePrice))
	mean := total / count
	median := 0.0
	sort.Float64s(cumulativePrice)
	switch {
	case count == 0:
		median = 0.0
	case len(cumulativePrice)%2 == 0:
		median = (cumulativePrice[len(cumulativePrice)/2-1] + cumulativePrice[len(cumulativePrice)/2]) / 2
	default:
		median = cumulativePrice[len(cumulativePrice)/2]
	}

	statType := model.StatisticTypeTotal
	duration := model.DurationPastDay
	result, err := g.client.GetBridgeAmountStatistic(g.GetTestContext(), statType, &duration, nil, nil, nil)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), fmt.Sprintf("%f", total), *result.Response.USDValue)

	statType = model.StatisticTypeCount
	result, err = g.client.GetBridgeAmountStatistic(g.GetTestContext(), statType, &duration, nil, nil, nil)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), fmt.Sprintf("%f", count), *result.Response.USDValue)

	statType = model.StatisticTypeMean
	result, err = g.client.GetBridgeAmountStatistic(g.GetTestContext(), statType, &duration, nil, nil, nil)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), fmt.Sprintf("%f", mean), *result.Response.USDValue)

	statType = model.StatisticTypeMedian
	result, err = g.client.GetBridgeAmountStatistic(g.GetTestContext(), statType, &duration, nil, nil, nil)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), fmt.Sprintf("%f", median), *result.Response.USDValue)
}

//nolint:cyclop
func (g APISuite) TestGetCountByChainID() {
	chainID := g.chainIDs[0]
	destinationChainIDA := g.chainIDs[1]
	destinationChainIDB := g.chainIDs[2]
	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))

	// Generate bridge events for different chain IDs.
	for blockNumber := uint64(1); blockNumber <= 10; blockNumber++ {
		var destinationChainID uint32
		if blockNumber%2 == 0 {
			destinationChainID = destinationChainIDA
		} else {
			destinationChainID = destinationChainIDB
		}

		currentTime := uint64(time.Now().Unix())
		txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainID,
			Recipient:          gosql.NullString{String: address.String(), Valid: true},
			DestinationChainID: big.NewInt(int64(destinationChainID)),
			BlockNumber:        blockNumber,
			TxHash:             txHash.String(),
			EventIndex:         gofakeit.Uint64(),
			TimeStamp:          &currentTime,
		})
		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDA, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDB, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
	}

	addressRef := address.String()
	directionRef := model.DirectionOut
	resultOut, err := g.client.GetCountByChainID(g.GetTestContext(), nil, &addressRef, &directionRef, nil)
	Nil(g.T(), err)
	// There should be 3 chains, 2 for the destination chain IDs and 1 for the source chain ID.
	Equal(g.T(), len(resultOut.Response), 3)
	// The source chain ID should have 10 events out, and the destination chain IDs should have 0 events out.
	var reached = 0
	for _, res := range resultOut.Response {
		switch *res.ChainID {
		case int(chainID):
			Equal(g.T(), *res.Count, 10)
			reached++
		case int(destinationChainIDA):
			Equal(g.T(), *res.Count, 0)
			reached++
		case int(destinationChainIDB):
			Equal(g.T(), *res.Count, 0)
			reached++
		}
	}
	Equal(g.T(), reached, 3)

	directionRef = model.DirectionIn
	resultIn, err := g.client.GetCountByChainID(g.GetTestContext(), nil, &addressRef, &directionRef, nil)
	Nil(g.T(), err)
	// Again, there should be 3 chains, 2 for the destination chain IDs and 1 for the source chain ID.
	Equal(g.T(), len(resultIn.Response), 3)
	// The source chain ID should have 0 events in, and the destination chain IDs should have 5 events in.
	reached = 0
	for _, res := range resultIn.Response {
		switch *res.ChainID {
		case int(chainID):
			Equal(g.T(), *res.Count, 0)
			reached++
		case int(destinationChainIDA):
			Equal(g.T(), *res.Count, 5)
			reached++
		case int(destinationChainIDB):
			Equal(g.T(), *res.Count, 5)
			reached++
		}
	}
	Equal(g.T(), reached, 3)
}

// nolint (needed for testing all possibilities)
func (g APISuite) TestGetCountByTokenAddress() {
	chainID := g.chainIDs[0]
	destinationChainID := g.chainIDs[1]
	tokenAddressA := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	tokenAddressB := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))

	// Generate bridge events for different chain IDs.
	for blockNumber := uint64(1); blockNumber <= 10; blockNumber++ {
		var tokenAddress common.Address
		if blockNumber%2 == 0 {
			tokenAddress = tokenAddressA
		} else {
			tokenAddress = tokenAddressB
		}
		currentTime := uint64(time.Now().Unix())
		txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainID,
			Recipient:          gosql.NullString{String: address.String(), Valid: true},
			DestinationChainID: big.NewInt(int64(destinationChainID)),
			Token:              tokenAddress.String(),
			BlockNumber:        blockNumber,
			TxHash:             txHash.String(),
			EventIndex:         gofakeit.Uint64(),
			TimeStamp:          &currentTime,
		})
		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainID, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
	}

	addressRef := address.String()
	directionRef := model.DirectionOut

	resultOut, err := g.client.GetCountByTokenAddress(g.GetTestContext(), nil, &addressRef, &directionRef, nil)
	Nil(g.T(), err)

	// There should be 4 results, two for each token on two chain. Each on the source chain ID should have 5 events,
	// while each on the destination chain ID should have 0 events.
	Equal(g.T(), len(resultOut.Response), 4)
	reached := 0
	for _, res := range resultOut.Response {
		if *res.ChainID == int(chainID) {
			if *res.TokenAddress == tokenAddressA.String() {
				Equal(g.T(), *res.Count, 5)
				reached++
			}
			if *res.TokenAddress == tokenAddressB.String() {
				Equal(g.T(), *res.Count, 5)
				reached++
			}
		}
		if *res.ChainID == int(destinationChainID) {
			if *res.TokenAddress == tokenAddressA.String() {
				Equal(g.T(), *res.Count, 0)
				reached++
			}
			if *res.TokenAddress == tokenAddressB.String() {
				Equal(g.T(), *res.Count, 0)
				reached++
			}
		}
	}
	Equal(g.T(), reached, 4)

	directionRef = model.DirectionIn
	resultIn, err := g.client.GetCountByTokenAddress(g.GetTestContext(), nil, nil, &directionRef, nil)
	Nil(g.T(), err)
	// Again, there should be 4 results, two for each token on two chain. Each on the source chain ID should have 0 events,
	// while each on the destination chain ID should have 5 events.
	Equal(g.T(), len(resultIn.Response), 4)
	reached = 0
	for _, res := range resultIn.Response {
		if *res.ChainID == int(destinationChainID) {
			if *res.TokenAddress == tokenAddressA.String() {
				Equal(g.T(), *res.Count, 5)
				reached++
			}
			if *res.TokenAddress == tokenAddressB.String() {
				Equal(g.T(), *res.Count, 5)
				reached++
			}
		}
		if *res.ChainID == int(chainID) {
			if *res.TokenAddress == tokenAddressA.String() {
				Equal(g.T(), *res.Count, 0)
				reached++
			}
			if *res.TokenAddress == tokenAddressB.String() {
				Equal(g.T(), *res.Count, 0)
				reached++
			}
		}
	}
	Equal(g.T(), reached, 4)
}

//nolint:cyclop
func (g APISuite) TestHistoricalStatistics() {
	chainID := g.chainIDs[0]
	destinationChainIDA := g.chainIDs[1]
	destinationChainIDB := g.chainIDs[2]
	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	tokenAddr := common.BigToAddress(big.NewInt(gofakeit.Int64())).String()
	nowTime := time.Now().Unix()
	senders := []string{common.BigToHash(big.NewInt(gofakeit.Int64())).String(), common.BigToHash(big.NewInt(gofakeit.Int64())).String(), common.BigToHash(big.NewInt(gofakeit.Int64())).String()}
	cumulativePrice := []float64{}
	// Generate bridge events for different chain IDs.
	for blockNumber := uint64(1); blockNumber <= 10; blockNumber++ {
		var destinationChainID uint32
		if blockNumber%2 == 0 {
			destinationChainID = destinationChainIDA
		} else {
			destinationChainID = destinationChainIDB
		}
		price := float64(gofakeit.Number(1, 300))
		cumulativePrice = append(cumulativePrice, price)
		txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
		timestamp := uint64(nowTime) - 100 - (10*blockNumber)*86400
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			ChainID:            chainID,
			Recipient:          gosql.NullString{String: address.String(), Valid: true},
			DestinationChainID: big.NewInt(int64(destinationChainID)),
			BlockNumber:        blockNumber,
			TxHash:             txHash.String(),
			EventIndex:         gofakeit.Uint64(),
			Token:              tokenAddr,
			Amount:             big.NewInt(int64(gofakeit.Number(1, 300))),
			AmountUSD:          &price,
			Sender:             senders[blockNumber%3],
			TimeStamp:          &timestamp,
		})
		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDA, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainIDB, blockNumber, uint64(time.Now().Unix())*blockNumber)
		Nil(g.T(), err)
	}

	days := 120
	chainIDInt := int(chainID)
	total := 0.0
	for _, v := range cumulativePrice {
		total += v
	}
	typeArg := model.HistoricalResultTypeBridgevolume
	result, err := g.client.GetHistoricalStatistics(g.GetTestContext(), &chainIDInt, &typeArg, &days)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), total, *result.Response.Total)
	Equal(g.T(), len(cumulativePrice), len(result.Response.DateResults))

	typeArg = model.HistoricalResultTypeAddresses
	result, err = g.client.GetHistoricalStatistics(g.GetTestContext(), &chainIDInt, &typeArg, &days)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), float64(3), *result.Response.Total)
	Equal(g.T(), len(cumulativePrice), len(result.Response.DateResults))

	typeArg = model.HistoricalResultTypeTransactions
	result, err = g.client.GetHistoricalStatistics(g.GetTestContext(), &chainIDInt, &typeArg, &days)
	Nil(g.T(), err)
	NotNil(g.T(), result)
	Equal(g.T(), float64(len(cumulativePrice)), *result.Response.Total)
	Equal(g.T(), len(cumulativePrice), len(result.Response.DateResults))
}

func (g APISuite) TestGetBridgeTransactions() {
	chainID := g.chainIDs[0]
	destinationChainID := g.chainIDs[1]

	tokenAddress := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	address := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	senderAddress := common.BigToAddress(big.NewInt(gofakeit.Int64()))
	senderString := senderAddress.String()
	txHashA := common.BigToHash(big.NewInt(gofakeit.Int64()))
	txHashB := common.BigToHash(big.NewInt(gofakeit.Int64()))
	kappaString := crypto.Keccak256Hash(txHashA.Bytes()).String()
	txHashString := txHashA.String()
	amount := big.NewInt(int64(gofakeit.Uint64()))
	amountUSD := float64(gofakeit.Number(1, 300))
	tokenDecimals := uint8(gofakeit.Number(0, 3))
	tokenSymbol := gofakeit.Word()
	timestamp := uint64(time.Now().Unix())
	page := 1

	g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
		InsertTime:         1,
		ContractAddress:    common.BigToAddress(big.NewInt(gofakeit.Int64())).String(),
		ChainID:            chainID,
		EventType:          gofakeit.Uint8(),
		Sender:             senderString,
		Recipient:          gosql.NullString{String: address.String(), Valid: true},
		DestinationChainID: big.NewInt(int64(destinationChainID)),
		Token:              tokenAddress.String(),
		BlockNumber:        1,
		TxHash:             txHashA.String(),
		DestinationKappa:   kappaString,
		EventIndex:         gofakeit.Uint64(),
		Amount:             amount,
		AmountUSD:          &amountUSD,
		TokenDecimal:       &tokenDecimals,
		TokenSymbol:        gosql.NullString{String: tokenSymbol, Valid: true},
		TimeStamp:          &timestamp,
	})
	g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
		InsertTime:         1,
		ContractAddress:    common.BigToAddress(big.NewInt(gofakeit.Int64())).String(),
		ChainID:            destinationChainID,
		EventType:          gofakeit.Uint8(),
		Recipient:          gosql.NullString{String: address.String(), Valid: true},
		DestinationChainID: big.NewInt(int64(chainID)),
		Token:              tokenAddress.String(),
		BlockNumber:        1,
		TxHash:             txHashB.String(),
		Kappa:              gosql.NullString{String: kappaString, Valid: true},
		SwapSuccess:        big.NewInt(1),
		EventIndex:         gofakeit.Uint64(),
		Amount:             amount,
		AmountUSD:          &amountUSD,
		TokenDecimal:       &tokenDecimals,
		Sender:             gofakeit.Word(),
		TokenSymbol:        gosql.NullString{String: tokenSymbol, Valid: true},
		TimeStamp:          &timestamp,
	})
	err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainID, 1, timestamp)
	Nil(g.T(), err)
	err = g.eventDB.StoreBlockTime(g.GetTestContext(), destinationChainID, 1, timestamp)
	Nil(g.T(), err)

	originRes, err := g.client.GetBridgeTransactions(g.GetTestContext(), nil, nil, &txHashString, nil, true, page, nil)
	Nil(g.T(), err)
	Equal(g.T(), len(originRes.Response), 1)
	originResOne := *originRes.Response[0]
	Equal(g.T(), *originResOne.Kappa, kappaString)
	// do pending
	Equal(g.T(), *originResOne.SwapSuccess, true)

	fromInfo := *originResOne.FromInfo
	Equal(g.T(), *fromInfo.ChainID, int(chainID))
	Equal(g.T(), *fromInfo.Address, address.String())
	Equal(g.T(), *fromInfo.TxnHash, txHashA.String())
	Equal(g.T(), *fromInfo.Value, amount.String())
	Equal(g.T(), *fromInfo.USDValue, amountUSD)
	formattedValue := float64(amount.Int64()) / math.Pow10(int(tokenDecimals))
	Equal(g.T(), *fromInfo.FormattedValue, formattedValue)
	Equal(g.T(), *fromInfo.TokenSymbol, tokenSymbol)
	Equal(g.T(), *fromInfo.TokenAddress, tokenAddress.String())
	Equal(g.T(), *fromInfo.BlockNumber, 1)
	Equal(g.T(), *fromInfo.Time, int(timestamp))

	toInfo := *originResOne.ToInfo
	Equal(g.T(), *toInfo.ChainID, int(destinationChainID))
	Equal(g.T(), *toInfo.Address, address.String())
	Equal(g.T(), *toInfo.TxnHash, txHashB.String())
	Equal(g.T(), *toInfo.Value, amount.String())
	Equal(g.T(), *toInfo.USDValue, amountUSD)
	Equal(g.T(), *toInfo.FormattedValue, formattedValue)
	Equal(g.T(), *toInfo.TokenSymbol, tokenSymbol)
	Equal(g.T(), *toInfo.TokenAddress, tokenAddress.String())
	Equal(g.T(), *toInfo.BlockNumber, 1)
	Equal(g.T(), *toInfo.Time, int(timestamp))

	destinationRes, err := g.client.GetBridgeTransactions(g.GetTestContext(), nil, nil, nil, &kappaString, true, page, nil)
	Nil(g.T(), err)
	Equal(g.T(), len(destinationRes.Response), 1)
	destinationResOne := *destinationRes.Response[0]
	Equal(g.T(), originResOne, destinationResOne)

	addressRes, err := g.client.GetBridgeTransactions(g.GetTestContext(), nil, &senderString, nil, nil, true, page, nil)
	Nil(g.T(), err)
	Equal(g.T(), len(addressRes.Response), 1)
	addressResOne := *addressRes.Response[0]
	Equal(g.T(), originResOne, addressResOne)
}

func (g APISuite) TestLatestBridgeTransaction() {
	var kappaStringA, kappaStringB string
	chainIDA := g.chainIDs[0]
	chainIDB := g.chainIDs[1]
	tokenDecimal := uint8(1)
	page := 1

	var blockNumber uint64
	// Generate multiple bridge events for different chain IDs.
	for {
		if blockNumber > 10 {
			break
		}
		txHashA := common.BigToHash(big.NewInt(gofakeit.Int64()))
		txHashB := common.BigToHash(big.NewInt(gofakeit.Int64()))
		kappaStringA = crypto.Keccak256Hash(txHashA.Bytes()).String()
		kappaStringB = crypto.Keccak256Hash(txHashB.Bytes()).String()
		currentTime := uint64(time.Now().Unix())
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainIDA,
			DestinationChainID: big.NewInt(int64(chainIDB)),
			BlockNumber:        blockNumber,
			TxHash:             txHashA.String(),
			DestinationKappa:   kappaStringA,
			Amount:             big.NewInt(int64(gofakeit.Uint32())),
			Kappa:              gosql.NullString{String: kappaStringB, Valid: true},
			Recipient:          gosql.NullString{String: gofakeit.Word(), Valid: true},
			TokenSymbol:        gosql.NullString{String: gofakeit.Word(), Valid: true},
			TokenDecimal:       &tokenDecimal,
			TimeStamp:          &currentTime,
		})
		g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
			InsertTime:         1,
			ChainID:            chainIDB,
			DestinationChainID: big.NewInt(int64(chainIDA)),
			BlockNumber:        blockNumber,
			TxHash:             txHashB.String(),
			DestinationKappa:   kappaStringB,
			Amount:             big.NewInt(int64(gofakeit.Uint32())),
			Kappa:              gosql.NullString{String: kappaStringA, Valid: true},
			Recipient:          gosql.NullString{String: gofakeit.Word(), Valid: true},
			TokenSymbol:        gosql.NullString{String: gofakeit.Word(), Valid: true},
			TokenDecimal:       &tokenDecimal,
			TimeStamp:          &currentTime,
		})
		// Set all times after current time, so we can get the events.
		err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDA, blockNumber, blockNumber)
		Nil(g.T(), err)
		err = g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDB, blockNumber, blockNumber)
		Nil(g.T(), err)
		blockNumber++
	}
	// Add one more bridge event without a completed destination event to test pending.
	txHash := common.BigToHash(big.NewInt(gofakeit.Int64()))
	kappaString := crypto.Keccak256Hash(txHash.Bytes()).String()
	newBlockNumber := blockNumber + 1
	currentTime := uint64(time.Now().Unix())
	g.db.UNSAFE_DB().WithContext(g.GetTestContext()).Create(&sql.BridgeEvent{
		InsertTime:         1,
		ChainID:            chainIDA,
		DestinationChainID: big.NewInt(int64(chainIDB)),
		BlockNumber:        blockNumber + 1,
		TxHash:             txHash.String(),
		DestinationKappa:   kappaString,
		Amount:             big.NewInt(int64(gofakeit.Uint32())),
		Recipient:          gosql.NullString{String: gofakeit.Word(), Valid: true},
		TokenSymbol:        gosql.NullString{String: gofakeit.Word(), Valid: true},
		TokenDecimal:       &tokenDecimal,
		TimeStamp:          &currentTime,
	})

	err := g.eventDB.StoreBlockTime(g.GetTestContext(), chainIDA, newBlockNumber, newBlockNumber)
	Nil(g.T(), err)
	// Get the latest bridge transactions.
	// Start with pending being true.
	bridgeTransactions, err := g.client.GetLatestBridgeTransactions(g.GetTestContext(), false, page)
	Nil(g.T(), err)
	Equal(g.T(), len(bridgeTransactions.Response), 2)
	for _, bridgeTransaction := range bridgeTransactions.Response {
		switch *bridgeTransaction.FromInfo.ChainID {
		case int(chainIDA):
			Equal(g.T(), *bridgeTransaction.Kappa, kappaStringA)
		case int(chainIDB):
			Equal(g.T(), *bridgeTransaction.Kappa, kappaStringB)
		}
	}
	// Then with pending being false
	bridgeTransactions, err = g.client.GetLatestBridgeTransactions(g.GetTestContext(), true, page)
	Nil(g.T(), err)
	Equal(g.T(), len(bridgeTransactions.Response), 2)
	for _, bridgeTransaction := range bridgeTransactions.Response {
		switch *bridgeTransaction.FromInfo.ChainID {
		case int(chainIDA):
			Equal(g.T(), *bridgeTransaction.Kappa, kappaString)
		case int(chainIDB):
			Equal(g.T(), *bridgeTransaction.Kappa, kappaStringB)
		}
	}
}
