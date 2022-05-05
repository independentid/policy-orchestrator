package policy

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"strings"
	"testing"
)

func TestUnMarshall(t *testing.T) {

	jsonBytes, err := ioutil.ReadFile("hexaPolicies_test.json")
	if err != nil {
		log.Fatalln("Error reading rego file: " + err.Error())
	}

	policies, err := UnmarshallJSONPolicies([]byte(jsonBytes))
	if err != nil {
		fmt.Println("Error parsing: " + err.Error())
	}
	assert.NoError(t, err)

	name := policies[0].Meta.ApplicationId
	assert.Equal(t, "CanaryBank1", name, "Parsed name should match")
	assert.Equal(t, 4, len(policies))
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
