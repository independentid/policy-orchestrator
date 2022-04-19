package policy

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestUnMarshall(t *testing.T) {
	jsonValue := `
[
	{
	"id": "CanaryProfileGoogleUpdate",
	"meta": {
	"version": "0.1",
	"date": "2021-08-01 21:32:44 UTC",
	"description": "Access enabling user self service for users with role",
	"applicationId": "CanaryBank1",
	"layer": "Browser"
	},
	"subject": {
	"type": "op",
	"providerId": "myGoogleIDP",
	"role": "canarySelfService"
	},
	"actions": [
	{
	"name": "createProfile",
	"actionUri": "accountCreate"
	},
	{ "name": "editProfile",
	"actionUri": "accountEdit"
	}
	],
	"object": {
	"assetId": "CanaryProfileService",
	"pathSpec": "/Profile/*"
	}
	},
	{
	"id": "EditProfileGoogleUpdate AdminContractor",
	"meta": {
	"version": "0.1",
	"date": "2021-08-01 21:32:44 UTC",
	"description": "Access policy enabling contract staff to edit profiles",
	"applicationId": "CanaryBank1",
	"layer": "Browser"
	},
	"subject": {
	"type": "op",
	"providerId": "myGoogleIDP"
	},
	"actions": [
	{
	"name": "editProfile",
	"actionUri": "accountEdit"
	}
	],
	"object": {
	"assetId": "CanaryProfileService",
	"pathSpec": "/Profile/*"
	},
	"condition": {
	"rule": "User:employeeType eq contract",
	"action": "allow"
	}
	},
	{
	"id": "CanaryProfileInternalNetUpdate",
	"meta": {
	"version": "0.1",
	"date": "2021-08-01 21:32:44 UTC",
	"description": "Enabling profile update for internal network services",
	"applicationId": "CanaryBank1",
	"layer": "Services"
	},
	"subject": {
	"type": "net",
	"cidr": "192.168.1.0/24",
	"members": ["WorkFlowSvcAcnt"]
	},
	"actions": [
	{
	"name": "createProfile",
	"actionUri": "accountCreate"
	},
	{ "name": "editProfile",
	"actionUri": "accountEdit"
	}
	],
	"object": {
	"assetId": "CanaryProfileService",
	"pathSpec": "/Profile/*"
	}
	}
]`

	policies, err := UnmarshallJSONPolicies([]byte(jsonValue))
	if err != nil {
		fmt.Println("Error parsing: " + err.Error())
	}
	assert.NoError(t, err)

	name := policies[0].Meta.ApplicationId
	assert.Equal(t, "CanaryBank1", name, "Parsed name should match")
	assert.Equal(t, 3, len(policies))
	assert.Equal(t, "CanaryProfileService", policies[2].Object.AssetId)
	assert.IsTypef(t, []HexaPolicy{}, policies, "Expecting type HexaPolicy")

}

func TestMarshall(t *testing.T) {
	policy := HexaPolicy{
		PolicyId: "1234",
		Meta: &MetaType{
			ApplicationId: "App1",
			Version:       "xyz",
			Date:          "2021-08-01 21:32:44 UTC",
			Description:   "This is a test",
			Layer:         "superficial",
		},
		Subject: SubjectType{
			Type: "anyAuthenticated",
			Role: "basic",
		},
		Actions: []ActionType{
			{
				Name:      "GetProfile",
				ActionUri: "ietf:http:GET",
				Exclude:   false,
			},
		},
		Object: ObjectType{
			AssetId:  "asset123",
			PathSpec: "/Profile",
		},
	}

	assert.Equal(t, "asset123", policy.Object.AssetId)

	policies := []HexaPolicy{policy}

	jsonBytes, err := MarshallJSONPolicies(policies, false)

	assert.NoError(t, err)

	jsonString := string(jsonBytes)

	assert.True(t, strings.HasPrefix(jsonString, `[{"id":"1234"`))
	assert.False(t, strings.Contains(jsonString, "providerId"))
	assert.False(t, strings.Contains(jsonString, "condition"))
	assert.True(t, strings.Contains(jsonString, "role"))

	jsonBytes, err = MarshallJSONPolicies(policies, true)
	assert.NoError(t, err)
	fmt.Println(string(jsonBytes))
}
