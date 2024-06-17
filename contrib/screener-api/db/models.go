// Package db provides the database interface for the screener-api.
package db

import (
	"time"

	"github.com/synapsecns/sanguine/contrib/screener-api/chainalysis"
)

// Entity is a Chainalysis entity.
type Entity struct {
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Address                string                              `gorm:"column:address"                json:"address"`
	Risk                   string                              `gorm:"column:risk"                   json:"risk"`
	RiskReason             string                              `gorm:"column:riskReason"             json:"riskReason"`
	Cluster                chainalysis.Cluster                 `gorm:"column:cluster"                json:"cluster"`
	AddressIdentifications []chainalysis.AddressIdentification `gorm:"column:addressIdentifications" json:"addressIdentifications"`
	Exposures              []chainalysis.Exposure              `gorm:"column:exposures"              json:"exposures"`
	Triggers               []chainalysis.Trigger               `gorm:"column:triggers"               json:"triggers"`
	Status                 string                              `gorm:"column:status"                 json:"status"`
}

// BlacklistedAddress is a blacklisted address.
type BlacklistedAddress struct {
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Type    string `gorm:"column:type"           json:"type"`
	ID      string `gorm:"column:id;primary_key" json:"id"`
	Data    string `gorm:"column:data"           json:"data"`
	Address string `gorm:"column:address"        json:"address"`
	Network string `gorm:"column:network"        json:"network"`
	Tag     string `gorm:"column:tag"            json:"tag"`
	Remark  string `gorm:"column:remark"         json:"remark"`
}
