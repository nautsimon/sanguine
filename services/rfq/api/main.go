// Package main is the entry point for the RFQ API Server
package main

import (
	"os"

	"github.com/synapsecns/sanguine/services/rfq/api/cmd"
	"github.com/synapsecns/sanguine/services/rfq/api/metadata"
)

//go:generate go run github.com/swaggo/swag/cmd/swag init

// main is the entry point for the RFQ API Server
func main() {
	cmd.Start(os.Args, metadata.BuildInfo())
}
