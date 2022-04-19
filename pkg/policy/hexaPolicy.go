package policy

import (
	"encoding/json"
)

// Note: Plan to incorporate JSON Schema Validation: see https://github.com/santhosh-tekuri/jsonschema

type MetaType struct {
	Version       string `json:"version,omitempty"`
	Date          string `json:"date,omitempty"` //Should be RFC822 format
	ETag          string `json:"etag,omitempty"`
	Description   string `json:"description,omitempty"`
	ApplicationId string `json:"applicationId,omitempty"`
	Layer         string `json:"layer,omitempty"`
}

const (
	subjectTypeAny           = "any"
	subjectTypeAuthenticated = "anyAuthenticated"
	subjectTypeBasic         = "basic"
)

type SubjectType struct {
	Type       string   `json:"type"`
	ProviderId string   `json:"providerId,omitempty"`
	Role       string   `json:"role,omitempty"`
	Members    []string `json:"members,omitempty"`
}

type ActionType struct {
	Name      string `json:"name,omitempty"`
	ActionUri string `json:"actionUri"`
	Exclude   bool   `json:"exclude,omitempty"`
}

type ObjectType struct {
	AssetId   string `json:"assetId"`
	PathSpec  string `json:"pathSpec,omitempty"`
	PathRegEx string `json:"pathRegEx,omitempty"`
}

type ScopeType struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ConditionType struct {
	Rule   string `json:"rule,omitempty"`
	Action string `json:"action,omitempty"`
}

type HexaPolicy struct {
	PolicyId  string         `json:"id,omitempty"`
	Meta      *MetaType      `json:"meta"`
	Subject   SubjectType    `json:"subject"`
	Actions   []ActionType   `json:"actions"`
	Object    ObjectType     `json:"object"`
	Scopes    []ScopeType    `json:"scopes,omitempty"`
	Condition *ConditionType `json:"condition,omitempty"`
}

func MarshallJSONPolicies(hexaPolicies []HexaPolicy, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(hexaPolicies, "", "  ")
	}
	return json.Marshal(hexaPolicies)
}

func UnmarshallJSONPolicies(jsonPolicyBytes []byte) ([]HexaPolicy, error) {
	var policy []HexaPolicy
	err := json.Unmarshal(jsonPolicyBytes, &policy)
	return policy, err
}
