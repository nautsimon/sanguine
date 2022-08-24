// Code generated by synapse abigen DO NOT EDIT.
package notarymanager

import (
	_ "embed"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common/compiler"
)

// rawContracts are the json we use to dervive the processed contracts
//
//go:embed notarymanager.contractinfo.json
var rawContracts []byte

// Contracts are unmarshalled on start
var Contracts map[string]*compiler.Contract

func init() {
	// load contract metadata
	var err error
	err = json.Unmarshal(rawContracts, &Contracts)
	if err != nil {
		panic(err)
	}
}
