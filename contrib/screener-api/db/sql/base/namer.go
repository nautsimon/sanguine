package base

import (
	"github.com/synapsecns/sanguine/core/dbcommon"
)

func init() {
	namer := dbcommon.NewNamer(GetAllModels())

	addressName = namer.GetConsistentName("Address")
	// riskName = namer.GetConsistentName("Risk")
	// riskReasonName = namer.GetConsistentName("RiskReason")
	// clusterName = namer.GetConsistentName("Cluster")
	// addressIdentificationsName = namer.GetConsistentName("AddressIdentifications")
	// exposuresName = namer.GetConsistentName("Exposures")
	// triggersName = namer.GetConsistentName("Triggers")
	// statusName = namer.GetConsistentName("Status")

	typeName = namer.GetConsistentName("Type")
	idName = namer.GetConsistentName("ID")
	dataName = namer.GetConsistentName("Data")
	networkName = namer.GetConsistentName("Network")
	tagName = namer.GetConsistentName("Tag")
	remarkName = namer.GetConsistentName("Remark")
}

var (
	addressName string
	// 	riskName                   string
	// 	riskReasonName             string
	// 	clusterName                string
	// 	addressIdentificationsName string
	// 	exposuresName              string
	// 	triggersName               string
	// 	statusName                 string

	typeName    string
	idName      string
	dataName    string
	networkName string
	tagName     string
	remarkName  string
)
