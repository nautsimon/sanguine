/*
 * types/v1/service.proto
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: version not set
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package rest

type V1FilterLogsRequest struct {
	Filter *V1LogFilter `json:"filter,omitempty"`
	Page   int64        `json:"page,omitempty"`
}
