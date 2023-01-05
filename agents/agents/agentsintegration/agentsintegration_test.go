package agentsintegration_test

import (
	"math/big"
	"time"

	"github.com/Flaque/filet"
	awsTime "github.com/aws/smithy-go/time"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/agents/agents/guard"
	"github.com/synapsecns/sanguine/agents/agents/notary"
	"github.com/synapsecns/sanguine/agents/config"
	"github.com/synapsecns/sanguine/agents/db/datastore/sql"
	"github.com/synapsecns/sanguine/agents/types"
	"github.com/synapsecns/sanguine/core/dbcommon"
)

// TestGuardAndNotaryOnlyIntegrationE2E is an integration involving just a guard and notary
// submitting a single message to the destination.
//
//nolint:dupl
func (u AgentsIntegrationSuite) TestGuardAndNotaryOnlyIntegrationE2E() {
	notaryTestConfig := config.NotaryConfig{
		DestinationDomain: u.DestinationDomainClient.Config(),
		AttestationDomain: u.AttestationDomainClient.Config(),
		OriginDomains: map[string]config.DomainConfig{
			"origin_client": u.OriginDomainClient.Config(),
		},
		BondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.NotaryBondedWallet.PrivateKeyHex()).Name(),
		},
		UnbondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.NotaryUnbondedWallet.PrivateKeyHex()).Name(),
		},
		Database: config.DBConfig{
			Type:       dbcommon.Sqlite.String(),
			DBPath:     filet.TmpDir(u.T(), ""),
			ConnString: filet.TmpDir(u.T(), ""),
		},
		RefreshIntervalInSeconds: 1,
	}
	guardTestConfig := config.GuardConfig{
		AttestationDomain: u.AttestationDomainClient.Config(),
		OriginDomains: map[string]config.DomainConfig{
			"origin_client": u.OriginDomainClient.Config(),
		},
		DestinationDomains: map[string]config.DomainConfig{
			"destination_client": u.DestinationDomainClient.Config(),
		},
		BondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.GuardBondedWallet.PrivateKeyHex()).Name(),
		},
		UnbondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.GuardUnbondedWallet.PrivateKeyHex()).Name(),
		},
		Database: config.DBConfig{
			Type:       dbcommon.Sqlite.String(),
			DBPath:     filet.TmpDir(u.T(), ""),
			ConnString: filet.TmpDir(u.T(), ""),
		},
		RefreshIntervalInSeconds: 1,
	}
	notary, err := notary.NewNotary(u.GetTestContext(), notaryTestConfig)
	Nil(u.T(), err)

	guard, err := guard.NewGuard(u.GetTestContext(), guardTestConfig)
	Nil(u.T(), err)

	guardDBType, err := dbcommon.DBTypeFromString(guardTestConfig.Database.Type)
	Nil(u.T(), err)

	guardDBHandle, err := sql.NewStoreFromConfig(u.GetTestContext(), guardDBType, guardTestConfig.Database.ConnString)
	Nil(u.T(), err)

	originAuth := u.TestBackendOrigin.GetTxContext(u.GetTestContext(), nil)

	encodedTips, err := types.EncodeTips(types.NewTips(big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)))
	Nil(u.T(), err)

	tx, err := u.OriginContract.Dispatch(
		originAuth.TransactOpts,
		u.DestinationDomainClient.Config().DomainID,
		[32]byte{},
		gofakeit.Uint32(),
		encodedTips,
		[]byte(gofakeit.Paragraph(3, 2, 1, " ")))
	Nil(u.T(), err)
	u.TestBackendOrigin.WaitForConfirmation(u.GetTestContext(), tx)

	go func() {
		// we don't check errors here since this will error on cancellation at the end of the test
		_ = notary.Start(u.GetTestContext())
	}()

	go func() {
		// we don't check errors here since this will error on cancellation at the end of the test
		_ = guard.Start(u.GetTestContext())
	}()

	u.Eventually(func() bool {
		_ = awsTime.SleepWithContext(u.GetTestContext(), time.Second*5)
		retrievedInProgressAttestation, err := guardDBHandle.RetrieveNewestConfirmedOnDestination(
			u.GetTestContext(),
			u.OriginDomainClient.Config().DomainID,
			u.DestinationDomainClient.Config().DomainID)

		isTrue := err == nil &&
			retrievedInProgressAttestation != nil &&
			retrievedInProgressAttestation.SignedAttestation().Attestation().Nonce() == uint32(1) &&
			u.OriginDomainClient.Config().DomainID == retrievedInProgressAttestation.SignedAttestation().Attestation().Origin() &&
			u.DestinationDomainClient.Config().DomainID == retrievedInProgressAttestation.SignedAttestation().Attestation().Destination() &&
			[32]byte{} != retrievedInProgressAttestation.SignedAttestation().Attestation().Root() &&
			len(retrievedInProgressAttestation.SignedAttestation().NotarySignatures()) == 1 &&
			len(retrievedInProgressAttestation.SignedAttestation().GuardSignatures()) == 1 &&
			retrievedInProgressAttestation.AttestationState() == types.AttestationStateConfirmedOnDestination

		return isTrue
	})
}

// TestGuardAndNotaryOnlyMultipleMessagesIntegrationE2E is an integration involving just a guard and notary
// submitting multiple messages to the destination.
//
//nolint:dupl,gocognit,cyclop
func (u AgentsIntegrationSuite) TestGuardAndNotaryOnlyMultipleMessagesIntegrationE2E() {
	numMessages := 5

	notaryTestConfig := config.NotaryConfig{
		DestinationDomain: u.DestinationDomainClient.Config(),
		AttestationDomain: u.AttestationDomainClient.Config(),
		OriginDomains: map[string]config.DomainConfig{
			"origin_client": u.OriginDomainClient.Config(),
		},
		BondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.NotaryBondedWallet.PrivateKeyHex()).Name(),
		},
		UnbondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.NotaryUnbondedWallet.PrivateKeyHex()).Name(),
		},
		Database: config.DBConfig{
			Type:       dbcommon.Sqlite.String(),
			DBPath:     filet.TmpDir(u.T(), ""),
			ConnString: filet.TmpDir(u.T(), ""),
		},
		RefreshIntervalInSeconds: 1,
	}
	guardTestConfig := config.GuardConfig{
		AttestationDomain: u.AttestationDomainClient.Config(),
		OriginDomains: map[string]config.DomainConfig{
			"origin_client": u.OriginDomainClient.Config(),
		},
		DestinationDomains: map[string]config.DomainConfig{
			"destination_client": u.DestinationDomainClient.Config(),
		},
		BondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.GuardBondedWallet.PrivateKeyHex()).Name(),
		},
		UnbondedSigner: config.SignerConfig{
			Type: config.FileType.String(),
			File: filet.TmpFile(u.T(), "", u.GuardUnbondedWallet.PrivateKeyHex()).Name(),
		},
		Database: config.DBConfig{
			Type:       dbcommon.Sqlite.String(),
			DBPath:     filet.TmpDir(u.T(), ""),
			ConnString: filet.TmpDir(u.T(), ""),
		},
		RefreshIntervalInSeconds: 1,
	}
	notary, err := notary.NewNotary(u.GetTestContext(), notaryTestConfig)
	Nil(u.T(), err)

	guard, err := guard.NewGuard(u.GetTestContext(), guardTestConfig)
	Nil(u.T(), err)

	guardDBType, err := dbcommon.DBTypeFromString(guardTestConfig.Database.Type)
	Nil(u.T(), err)

	guardDBHandle, err := sql.NewStoreFromConfig(u.GetTestContext(), guardDBType, guardTestConfig.Database.ConnString)
	Nil(u.T(), err)

	originAuth := u.TestBackendOrigin.GetTxContext(u.GetTestContext(), nil)

	encodedTips, err := types.EncodeTips(types.NewTips(big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)))
	Nil(u.T(), err)

	for i := 0; i < numMessages; i++ {
		tx, err := u.OriginContract.Dispatch(
			originAuth.TransactOpts,
			u.DestinationDomainClient.Config().DomainID,
			[32]byte{},
			gofakeit.Uint32(),
			encodedTips,
			[]byte(gofakeit.Paragraph(3, 2, 1, " ")))
		Nil(u.T(), err)
		u.TestBackendOrigin.WaitForConfirmation(u.GetTestContext(), tx)
		currRoot, currDispatchBlockNumber, err := u.OriginContract.GetHistoricalRoot(&bind.CallOpts{Context: u.GetTestContext()}, u.DestinationDomainClient.Config().DomainID, uint32(i+1))
		Nil(u.T(), err)
		Greater(u.T(), currDispatchBlockNumber.Uint64(), uint64(0))
		NotEqual(u.T(), [32]byte{}, currRoot)
	}

	go func() {
		// we don't check errors here since this will error on cancellation at the end of the test
		_ = notary.Start(u.GetTestContext())
	}()

	go func() {
		// we don't check errors here since this will error on cancellation at the end of the test
		_ = guard.Start(u.GetTestContext())
	}()

	u.Eventually(func() bool {
		_ = awsTime.SleepWithContext(u.GetTestContext(), time.Second*5)
		retrievedInProgressAttestation, err := guardDBHandle.RetrieveNewestConfirmedOnDestination(
			u.GetTestContext(),
			u.OriginDomainClient.Config().DomainID,
			u.DestinationDomainClient.Config().DomainID)

		isTrue := err == nil &&
			retrievedInProgressAttestation != nil &&
			retrievedInProgressAttestation.SignedAttestation().Attestation().Nonce() == uint32(numMessages) &&
			u.OriginDomainClient.Config().DomainID == retrievedInProgressAttestation.SignedAttestation().Attestation().Origin() &&
			u.DestinationDomainClient.Config().DomainID == retrievedInProgressAttestation.SignedAttestation().Attestation().Destination() &&
			[32]byte{} != retrievedInProgressAttestation.SignedAttestation().Attestation().Root() &&
			len(retrievedInProgressAttestation.SignedAttestation().NotarySignatures()) == 1 &&
			len(retrievedInProgressAttestation.SignedAttestation().GuardSignatures()) == 1 &&
			retrievedInProgressAttestation.AttestationState() == types.AttestationStateConfirmedOnDestination

		if isTrue {
			for i := 0; i < numMessages; i++ {
				currNonce := uint32(i + 1)
				currInProgressAttestation, err := guardDBHandle.RetrieveInProgressAttestation(
					u.GetTestContext(),
					u.OriginDomainClient.Config().DomainID,
					u.DestinationDomainClient.Config().DomainID,
					currNonce)
				if err != nil {
					return false
				}
				if currInProgressAttestation.AttestationState() != types.AttestationStateConfirmedOnDestination {
					return false
				}
			}
		}

		return isTrue
	})
}
