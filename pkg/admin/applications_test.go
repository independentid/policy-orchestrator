package admin_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hexa-org/policy-orchestrator/pkg/admin"
	"github.com/hexa-org/policy-orchestrator/pkg/admin/test"
	"github.com/hexa-org/policy-orchestrator/pkg/healthsupport"
	idqlPolicy "github.com/hexa-org/policy-orchestrator/pkg/policy"
	"github.com/hexa-org/policy-orchestrator/pkg/websupport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type ApplicationsSuite struct {
	suite.Suite
	server *http.Server
	client *admin_test.MockClient
}

func TestApplications(t *testing.T) {
	suite.Run(t, new(ApplicationsSuite))
}

func (suite *ApplicationsSuite) SetupTest() {
	_, file, _, _ := runtime.Caller(0)
	resourcesDirectory := filepath.Join(file, "../../../pkg/admin/resources")

	listener, _ := net.Listen("tcp", "localhost:0")
	suite.client = new(admin_test.MockClient)
	suite.server = websupport.Create(
		listener.Addr().String(),
		admin.LoadHandlers("http://noop", suite.client),
		websupport.Options{ResourceDirectory: resourcesDirectory})
	go websupport.Start(suite.server, listener)
	healthsupport.WaitForHealthy(suite.server)
}

func (suite *ApplicationsSuite) TearDownTest() {
	websupport.Stop(suite.server)
}

func (suite *ApplicationsSuite) TestApplications() {
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications", suite.server.Addr))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Applications")
	assert.Contains(suite.T(), string(body), "anObjectId")
	assert.Contains(suite.T(), string(body), "aName")
	assert.Contains(suite.T(), string(body), "aDescription")
}

func (suite *ApplicationsSuite) TestApplications_templateRenders() {
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications", suite.server.Addr))
	body, _ := io.ReadAll(resp.Body)

	assert.Contains(suite.T(), string(body), "Platform Identifier")
	assert.Contains(suite.T(), string(body), "Name")
	assert.Contains(suite.T(), string(body), "Description")
}

func (suite *ApplicationsSuite) TestApplications_with_error() {
	suite.client.Err = errors.New("oops")
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications", suite.server.Addr))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Something went wrong.")
}

func (suite *ApplicationsSuite) TestApplication() {
	identifier := "anId"
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications/%s", suite.server.Addr, identifier))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Applications")
	assert.Contains(suite.T(), string(body), "anObjectId")
	assert.Contains(suite.T(), string(body), "aName")
	assert.Contains(suite.T(), string(body), "aDescription")

	assert.Contains(suite.T(), string(body), "aVersion")
	assert.Contains(suite.T(), string(body), "anotherAction")
	assert.Contains(suite.T(), string(body), "anotherUser")
}

func (suite *ApplicationsSuite) TestApplication_withErroneousGet() {
	suite.client.Err = errors.New("oops")
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications/000", suite.server.Addr))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Something went wrong.")
	assert.Contains(suite.T(), string(body), "Unable to contact orchestrator.")
}

func (suite *ApplicationsSuite) TestApplication_Edit() {
	identifier := "anId"
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications/%s/edit", suite.server.Addr, identifier))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Applications")
	assert.Contains(suite.T(), string(body), "anObjectId")
	assert.Contains(suite.T(), string(body), "aName")
	assert.Contains(suite.T(), string(body), "aDescription")

	assert.Contains(suite.T(), string(body), "action=\"/applications/anId\"")
}

func (suite *ApplicationsSuite) TestApplication_Edit_withErroneousGet() {
	suite.client.Err = errors.New("oops")
	identifier := "anId"
	resp, _ := http.Get(fmt.Sprintf("http://%s/applications/%s/edit", suite.server.Addr, identifier))
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Something went wrong.")
	assert.Contains(suite.T(), string(body), "Unable to contact orchestrator.")
}

func (suite *ApplicationsSuite) TestApplication_Update() {
	identifier := "anId"
	resp, _ := http.Post(fmt.Sprintf("http://%s/applications/%s", suite.server.Addr, identifier), "application/json", nil)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Applications")
	assert.Contains(suite.T(), string(body), "anObjectId")
	assert.Contains(suite.T(), string(body), "aName")
	assert.Contains(suite.T(), string(body), "aDescription")

	assert.Contains(suite.T(), string(body), "aVersion")
	assert.Contains(suite.T(), string(body), "anotherAction")
	assert.Contains(suite.T(), string(body), "anotherUser")
}

func (suite *ApplicationsSuite) TestApplication_Update_withErroneousGet() {
	suite.client.Err = errors.New("oops")
	identifier := "anId"
	resp, _ := http.Post(fmt.Sprintf("http://%s/applications/%s", suite.server.Addr, identifier), "application/json", nil)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(suite.T(), string(body), "Something went wrong.")
	assert.Contains(suite.T(), string(body), "Unable to contact orchestrator.")
}

func TestMigration(t *testing.T) {
	hexaPolicy := idqlPolicy.HexaPolicy{
		PolicyId: "1234",
		Meta: &idqlPolicy.MetaType{
			ApplicationId: "App1",
			Version:       "xyz",
			Date:          "2021-08-01 21:32:44 UTC",
			Description:   "This is a test",
			Layer:         "superficial",
		},
		Subject: idqlPolicy.SubjectType{
			Type: "anyAuthenticated",
			Role: "basic",
		},
		Actions: []idqlPolicy.ActionType{
			{
				Name:      "GetProfile",
				ActionUri: "ietf:http:GET",
				Exclude:   false,
			},
		},
		Object: idqlPolicy.ObjectType{
			AssetId:  "asset123",
			PathSpec: "/Profile",
		},
	}

	// Old fashioned policy should continue to serialize as before
	policy1 := admin.Policy{Version: "aVersion", Action: "anAction", Subject: admin.Subject{AuthenticatedUsers: []string{"aUser"}}, Object: admin.Object{Resources: []string{"/"}}}
	assert.False(t, policy1.IsV2Policy())
	jsonBytes, err := json.Marshal(policy1)
	assert.NoError(t, err)
	jsonString := string(jsonBytes)
	assert.False(t, strings.Contains(jsonString, "hexaPolicy"))

	// New policy should have null/nil values and and a hexaPolicy Value
	policy2 := admin.CreateV2Policy(&hexaPolicy)
	assert.True(t, policy2.IsV2Policy())
	jsonBytes, err = json.Marshal(policy2)
	assert.NoError(t, err)
	jsonString = string(jsonBytes)
	assert.True(t, strings.Contains(jsonString, "hexaPolicy"))

}
