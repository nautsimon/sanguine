package screener_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Flaque/filet"
	"github.com/phayes/freeport"
	. "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/synapsecns/sanguine/contrib/screener-api/chainalysis"
	"github.com/synapsecns/sanguine/contrib/screener-api/client"
	"github.com/synapsecns/sanguine/contrib/screener-api/config"
	"github.com/synapsecns/sanguine/contrib/screener-api/metadata"
	"github.com/synapsecns/sanguine/contrib/screener-api/screener"
	"github.com/synapsecns/sanguine/core"
	"github.com/synapsecns/sanguine/core/dbcommon"
	"github.com/synapsecns/sanguine/core/metrics"
	"github.com/synapsecns/sanguine/core/metrics/localmetrics"
	"github.com/synapsecns/sanguine/core/testsuite"
)

type ScreenerSuite struct {
	*testsuite.TestSuite
	metrics metrics.Handler
	port    int
}

// NewScreenerSuite creates a new screener test suite.
func NewScreenerSuite(tb testing.TB) *ScreenerSuite {
	tb.Helper()
	return &ScreenerSuite{TestSuite: testsuite.NewTestSuite(tb)}
}

func TestScreenerSuite(t *testing.T) {
	suite.Run(t, NewScreenerSuite(t))
}

// TestScreenerSuite runs the screener test suite.
func (s *ScreenerSuite) SetupSuite() {
	s.TestSuite.SetupSuite()

	isCI := core.GetEnvBool("CI", false)
	useMetrics := !isCI
	metricsHandler := metrics.Null

	if useMetrics {
		localmetrics.SetupTestJaeger(s.GetSuiteContext(), s.T())
		metricsHandler = metrics.Jaeger
	}

	var err error
	s.metrics, err = metrics.NewByType(s.GetSuiteContext(), metadata.BuildInfo(), metricsHandler)
	Nil(s.T(), err)
}

func (s *ScreenerSuite) TestScreener() {
	var err error

	s.port, err = freeport.GetFreePort()
	Nil(s.T(), err)

	s.T().Setenv("TRM_URL", "")

	cfg := config.Config{
		AppSecret:    "secret",
		AppID:        "appid",
		BlacklistURL: "https://synapseprotocol.com/blacklist.json", // TODO: mock this out
		Port:         s.port,
		Database: config.DatabaseConfig{
			Type: dbcommon.Sqlite.String(),
			DSN:  filet.TmpDir(s.T(), ""),
		},
	}

	realScreener, err := screener.NewTestScreener(s.GetTestContext(), cfg, s.metrics)
	Nil(s.T(), err)
	NotNil(s.T(), realScreener)
	go func() {
		err = realScreener.Start(s.GetTestContext())
		if !errors.Is(err, context.Canceled) {
			Nil(s.T(), err)
		}
	}()

	m := mockClient{
		entityMap: map[string]*chainalysis.Entity{
			"0x123": {
				Address:    "0x123",
				Risk:       "low",
				RiskReason: "none",
				Cluster:    chainalysis.Cluster{Name: "Cluster A", Category: "Category 1"},
				AddressIdentifications: []chainalysis.AddressIdentification{
					{
						Name:        "Name A",
						Category:    "Category A",
						Description: "Description A",
					},
				},
				Exposures: []chainalysis.Exposure{{Category: "Exposure A", Value: 100.0}},
				Triggers: []chainalysis.Trigger{
					{
						Category:      "Trigger A",
						Percentage:    0.1,
						Message:       "Message A",
						RuleTriggered: chainalysis.RuleTriggered{Risk: "low", MinThreshold: 0.0, MaxThreshold: 1.0},
					},
				},
				Status: "active",
			},
			"0x456": {
				Address:    "0x456",
				Risk:       "high",
				RiskReason: "fraud",
				Cluster:    chainalysis.Cluster{Name: "Cluster B", Category: "Category 2"},
				AddressIdentifications: []chainalysis.AddressIdentification{
					{
						Name:        "Name B",
						Category:    "Category B",
						Description: "Description B",
					},
				},
				Exposures: []chainalysis.Exposure{{Category: "Exposure B", Value: 200.0}},
				Triggers: []chainalysis.Trigger{
					{
						Category:   "Trigger B",
						Percentage: 0.2,
						Message:    "Message B",
						RuleTriggered: chainalysis.RuleTriggered{
							Risk:         "high",
							MinThreshold: 1.0,
							MaxThreshold: 2.0,
						},
					},
				},
				Status: "inactive",
			},
		},
	}

	realScreener.SetClient(m)
	time.Sleep(time.Second)

	apiClient, err := client.NewClient(s.metrics, fmt.Sprintf("http://localhost:%d", s.port))
	Nil(s.T(), err)

	// http://localhost:63575/testrule/address/0x123: true
	out, err := apiClient.ScreenAddress(s.GetTestContext(), "0x123")
	Nil(s.T(), err)
	True(s.T(), out)

	// http://localhost:63575/testrule/address/0x00: false
	out, err = apiClient.ScreenAddress(s.GetTestContext(), "0x00")
	Nil(s.T(), err)
	False(s.T(), out)

	// now test crud screener
	blacklistBody := client.BlackListBody{
		Type:    "create",
		ID:      "1",
		Data:    "{\"test\":\"data\"}",
		Address: "0x123",
		Network: "eth",
		Tag:     "tag",
		Remark:  "remark",
	}

	// post to the blacklist
	status, err := apiClient.BlacklistAddress(s.GetTestContext(), cfg.AppSecret, cfg.AppID, blacklistBody)
	fmt.Println(status)
	Equal(s.T(), "success", status)
	Nil(s.T(), err)

	// update an address on the blacklist
	blacklistBody.Type = "update"
	blacklistBody.Remark = "new remark"

	status, err = apiClient.BlacklistAddress(s.GetTestContext(), cfg.AppSecret, cfg.AppID, blacklistBody)
	fmt.Println(status)
	Equal(s.T(), "success", status)
	Nil(s.T(), err)

	// delete the address on the blacklist
	blacklistBody.Type = "delete"
	blacklistBody.ID = "1"

	status, err = apiClient.BlacklistAddress(s.GetTestContext(), cfg.AppSecret, cfg.AppID, blacklistBody)
	fmt.Println(status)
	Equal(s.T(), "success", status)
	Nil(s.T(), err)

	// unauthorized
	status, err = apiClient.BlacklistAddress(s.GetTestContext(), "bad", cfg.AppID, blacklistBody)
	fmt.Println(status)
	NotEqual(s.T(), "success", status)
	NotNil(s.T(), err)
}

type mockClient struct {
	entityMap map[string]*chainalysis.Entity
}

// ScreenAddress mocks the screen address method.
func (m mockClient) ScreenAddress(ctx context.Context, address string) (*chainalysis.Entity, error) {
	if m.entityMap == nil {
		return nil, fmt.Errorf("no response map")
	}

	return m.entityMap[address], nil
}

var _ chainalysis.Client = mockClient{}
