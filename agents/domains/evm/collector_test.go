package evm_test

import (
	"math/big"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	. "github.com/stretchr/testify/assert"
	"github.com/synapsecns/sanguine/agents/types"
	"github.com/synapsecns/sanguine/core"
)

func (i ContractSuite) TestSubmitAttestation() {
	originDomain := uint32(i.TestBackendOrigin.GetChainID())
	destinationDomain := uint32(i.TestBackendDestination.GetChainID())

	nonce := gofakeit.Uint32()
	root := common.BigToHash(new(big.Int).SetUint64(gofakeit.Uint64()))
	attestKey := types.AttestationKey{
		Origin:      originDomain,
		Destination: destinationDomain,
		Nonce:       nonce,
	}
	unsignedAttestation := types.NewAttestation(attestKey.GetRawKey(), root)
	hashedAttestation, err := types.Hash(unsignedAttestation)
	Nil(i.T(), err)

	notarySignature, err := i.NotarySigner.SignMessage(i.GetTestContext(), core.BytesToSlice(hashedAttestation), false)
	Nil(i.T(), err)

	signedAttestation := types.NewSignedAttestation(unsignedAttestation, []types.Signature{}, []types.Signature{notarySignature})
	rawSignedAttestation, err := types.EncodeSignedAttestation(signedAttestation)
	Nil(i.T(), err)

	auth := i.TestBackendAttestation.GetTxContext(i.GetTestContext(), nil)

	tx, err := i.AttestationContract.SubmitAttestation(auth.TransactOpts, rawSignedAttestation)
	Nil(i.T(), err)

	i.TestBackendAttestation.WaitForConfirmation(i.GetTestContext(), tx)

	latestNonce, err := i.AttestationContract.GetLatestNonce(&bind.CallOpts{Context: i.GetTestContext()}, originDomain, destinationDomain, i.NotarySigner.Address())
	Nil(i.T(), err)
	Equal(i.T(), nonce, latestNonce)

	retrievedRawSignedAttestation, err := i.AttestationContract.GetAttestation(&bind.CallOpts{Context: i.GetTestContext()}, originDomain, destinationDomain, nonce)
	Nil(i.T(), err)
	retrievedSignedAttestation, err := types.DecodeSignedAttestation(retrievedRawSignedAttestation)
	Nil(i.T(), err)
	Equal(i.T(), signedAttestation.Attestation().Origin(), retrievedSignedAttestation.Attestation().Origin())
	Equal(i.T(), signedAttestation.Attestation().Destination(), retrievedSignedAttestation.Attestation().Destination())
	Equal(i.T(), signedAttestation.Attestation().Root(), retrievedSignedAttestation.Attestation().Root())
	Equal(i.T(), signedAttestation.Attestation().Nonce(), retrievedSignedAttestation.Attestation().Nonce())

	retrievedRoot, err := i.AttestationContract.GetRoot(&bind.CallOpts{Context: i.GetTestContext()}, originDomain, destinationDomain, nonce)
	Nil(i.T(), err)
	Equal(i.T(), signedAttestation.Attestation().Root(), retrievedRoot)
}
