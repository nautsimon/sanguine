package base_test

import (
	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/common"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/agents/agents/executor/db/datastore/sql/base"
	"github.com/synapsecns/sanguine/agents/agents/executor/types"
	"math/big"
	"testing"
)

func TestAttestationDBAttestationParity(t *testing.T) {
	destination := gofakeit.Uint32()
	snapshotRoot := common.BigToHash(big.NewInt(gofakeit.Int64())).String()
	height := gofakeit.Uint8()
	attestationNonce := gofakeit.Uint32()
	summitBlockNumber := gofakeit.Uint64()
	summitTimestamp := gofakeit.Uint64()
	destinationBlockNumber := gofakeit.Uint64()
	destinationTimestamp := gofakeit.Uint64()

	initialDBAttestation := types.DBAttestation{
		Destination:            &destination,
		SnapshotRoot:           &snapshotRoot,
		Height:                 &height,
		AttestationNonce:       &attestationNonce,
		SummitBlockNumber:      &summitBlockNumber,
		SummitTimestamp:        &summitTimestamp,
		DestinationBlockNumber: &destinationBlockNumber,
		DestinationTimestamp:   &destinationTimestamp,
	}

	initialAttestation := base.DBAttestationToAttestation(initialDBAttestation)

	finalDBAttestation := base.AttestationToDBAttestation(initialAttestation)

	finalAttestation := base.DBAttestationToAttestation(finalDBAttestation)

	Equal(t, initialDBAttestation, finalDBAttestation)
	Equal(t, initialAttestation, finalAttestation)
}
