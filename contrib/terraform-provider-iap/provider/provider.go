// Package provider gets the provider for the iap tunnel.
package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/synapsecns/sanguine/contrib/terraform-provider-iap/generated/google"
)

// Provider gets the provider for the iap tunnel.
func Provider() *schema.Provider {
	underlyingProvider := google.Provider()
	return &schema.Provider{
		Schema:               underlyingProvider.Schema,
		ProviderMetaSchema:   underlyingProvider.ProviderMetaSchema,
		ConfigureContextFunc: underlyingProvider.ConfigureContextFunc,
		DataSourcesMap: map[string]*schema.Resource{
			"iap_tunnel_proxy": dataSourceProxyURL(),
		},
	}
}
