package decisionsupportproviders_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/hexa-org/policy-orchestrator/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-orchestrator/pkg/healthsupport"
	opaTools "github.com/hexa-org/policy-orchestrator/pkg/policy/opa"
	"github.com/hexa-org/policy-orchestrator/pkg/websupport"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOpaDecisionProvider_BuildInput_BuildInput(t *testing.T) {
	provider := decisionsupportproviders.OpaDecisionProvider{}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	assert.Equal(t, "GET", casted["req"].(*decisionsupportproviders.ReqParams).Method)
	assert.Equal(t, "/noop", casted["req"].(*decisionsupportproviders.ReqParams).Path)
}

type MockClient struct {
	mock.Mock
	response []byte
	err      error
}

func (m *MockClient) Do(_ *http.Request) (*http.Response, error) {
	r := ioutil.NopCloser(bytes.NewReader(m.response))
	return &http.Response{StatusCode: 200, Body: r}, m.err
}

func TestOpaDecisionProvider_Allow(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req)

	allow, _ := provider.Allow(query)
	assert.Equal(t, true, allow)
}

func TestOpaDecisionProvider_AllowWithRequestErr(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	mockClient.err = errors.New("oops")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req)

	allow, err := provider.Allow(query)
	assert.Equal(t, "oops", err.Error())
	assert.Equal(t, false, allow)
}

func TestOpaDecisionProvider_AllowWithResponseErr(t *testing.T) {
	mockClient := new(MockClient)
	mockClient.response = []byte("__bad__ {\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req)

	allow, err := provider.Allow(query)
	assert.Equal(t, "invalid character '_' looking for beginning of value", err.Error())
	assert.Equal(t, false, allow)
}

func TestOpaDecisionAnonymous(t *testing.T) {

	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.RequestURI = "/noop"
	req.RemoteAddr = "127.0.0.1:8888"
	req.Header.Set("a", "b")
	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	reqInfo := casted["req"].(*decisionsupportproviders.ReqParams)
	assert.NotNil(t, reqInfo)
	assert.Equal(t, "GET", reqInfo.Method)
	assert.Equal(t, "/noop", reqInfo.Path)
	assert.True(t, strings.HasPrefix(reqInfo.ClientIp, "127.0.0.1:"))

	reqTime := reqInfo.Time
	assert.True(t, reqTime.Before(time.Now()))

	subInfo := casted["subject"].(*decisionsupportproviders.SubjectInfo)
	assert.Equal(t, "Anonymous", subInfo.Type)
	assert.Equal(t, 1, len(reqInfo.Header))
}

func TestOpaDecisionBasicAuth(t *testing.T) {

	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	req, _ := http.NewRequest("GET", "http://aDomain.com/noop", nil)
	req.SetBasicAuth("testUser", "good&bad")
	req.RequestURI = "/noop"
	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	subInfo := casted["subject"].(*decisionsupportproviders.SubjectInfo)
	assert.Equal(t, "basic", subInfo.Type)
	assert.Equal(t, "testUser", subInfo.Sub)
}

func TestJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln("Unexpected error setting verify key")
	}

	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	toknstr, err := GenerateBearerToken(key, "TestUser", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://adomain.com/testpath?a=b&c=d"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)

	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	reqInfo := casted["req"].(*decisionsupportproviders.ReqParams)
	subInfo := casted["subject"].(*decisionsupportproviders.SubjectInfo)

	assert.NotNil(t, reqInfo)
	assert.NotNil(t, reqInfo.ClientIp)
	reqTime := reqInfo.Time
	assert.True(t, reqTime.Before(time.Now()))

	assert.Equal(t, "Bearer+JWT", subInfo.Type)
	assert.Equal(t, "TestUser", subInfo.Sub)
	assert.Equal(t, 1, len(reqInfo.Header))
}

func TestExpiredJwtAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln("Unexpected error setting verify key")
	}

	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	oldDate := time.Date(2020, 1, 1, 12, 00, 0, 0, time.UTC)
	toknstr, err := GenerateBearerToken(key, "TestUser", oldDate)
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://aDomain.com/testpath?a=b&c=d"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	subInfo := casted["subject"].(*decisionsupportproviders.SubjectInfo)

	assert.True(t, strings.HasPrefix(subInfo.Type, "Invalid"))
}

func TestUnknownAuth(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln("Unexpected error setting verify key")
	}
	mockClient := new(MockClient)
	mockClient.response = []byte("{\"result\":true}")
	provider := decisionsupportproviders.OpaDecisionProvider{Client: mockClient, Url: "aUrl"}

	oldDate := time.Date(2020, 1, 1, 12, 00, 0, 0, time.UTC)
	toknstr, err := GenerateBearerToken(key, "TestUser", oldDate)
	if err != nil {
		log.Fatalln(err)
	}
	authz := "NotReal " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://aDomain.com/testpath?a=b&c=d"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	query, _ := provider.BuildInput(req)
	casted := query.(decisionsupportproviders.OpaQuery).Input

	subInfo := casted["subject"].(*decisionsupportproviders.SubjectInfo)

	assert.True(t, strings.HasPrefix(subInfo.Type, "Unknown-"))
}

/*
The following section excercises the Allow method and validates OPA Policy code
*/

const regoV0path = "../decisionsupport/resources/hexaPolicyV0_1.rego"
const dataV0path = "../decisionsupport/resources/test/data-V0_1.json"

func TestAllowBasic(t *testing.T) {
	client := &http.Client{Timeout: time.Minute * 2}
	provider := decisionsupportproviders.OpaDecisionProvider{Client: client, Url: "/auth/hexaPolicy"}
	opaServer := GetMockOpaServer(&provider)
	assert.NotNil(t, opaServer)

	// Test #1 Should be allowed
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://adomain.com/marketing"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("sales@hexaindustries.io", "good&bad")

	input, _ := provider.BuildInput(req)
	isAllowed, err := provider.Allow(input)

	assert.Equal(t, true, isAllowed)

	// Test #2 Should fail
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://adomain.com/notBueno"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("sales@hexaindustries.io", "good&bad")

	input, _ = provider.BuildInput(req)
	isAllowed, err = provider.Allow(input)

	assert.Equal(t, false, isAllowed)

	websupport.Stop(opaServer)
}

func TestAllowJwt(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"

	// Should this be part of the provider struct?
	err := os.Setenv("OPATOOLS_JWTVERIFYKEY", key)
	if err != nil {
		log.Fatalln("Unexpected error setting verify key")
	}
	client := &http.Client{Timeout: time.Minute * 2}
	provider := decisionsupportproviders.OpaDecisionProvider{Client: client, Url: "/auth/hexaPolicy"}
	opaServer := GetMockOpaServer(&provider)
	assert.NotNil(t, opaServer)

	toknstr, err := GenerateBearerToken(key, "sales@hexaindustries.io", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://adomain.com/marketing"), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)

	input, _ := provider.BuildInput(req)
	isAllowed, err := provider.Allow(input)

	assert.Equal(t, true, isAllowed)

	websupport.Stop(opaServer)
}

func GenerateBearerToken(key string, subject string, expires time.Time) (string, error) {
	claims := &opaTools.HexaClaims{
		&jwt.StandardClaims{
			Issuer:    "testIssuer",
			Audience:  "testAudience",
			ExpiresAt: expires.Unix(),
			Subject:   subject,
		},
		"bearer abc",
	}

	t := jwt.New(jwt.GetSigningMethod("HS256"))
	t.Claims = claims
	return t.SignedString([]byte(key))
}

/*
 This is a mock OPA server that processes the input provided against a test set of policy rules and data (regoV0path, dataV0path)
*/
func GetMockOpaServer(provider *decisionsupportproviders.OpaDecisionProvider) *http.Server {

	serveUrl, _ := url.Parse(provider.Url)
	path := serveUrl.Path
	serveUrl.Scheme = "http"
	listener, _ := net.Listen("tcp", "localhost:0")

	// Need to fix this so it will just serve anything for policy testing
	server := websupport.Create(listener.Addr().String(), func(router *mux.Router) {
		router.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			ctx := context.Background()

			// Load the rego to evaluate Hexa Policy
			regoBytes, err := ioutil.ReadFile(regoV0path)
			if err != nil {
				log.Fatalln("Error reading rego file: " + err.Error())
			}

			// Load the Configurable Hexa Policy statements
			dataBytes, err := ioutil.ReadFile(dataV0path)
			if err != nil {
				log.Fatalln("Error reading data file: " + err.Error())
			}

			var dataJson map[string]interface{}
			err = util.UnmarshalJSON(dataBytes, &dataJson)
			if err != nil {
				log.Fatalln("Error parsing data file: " + err.Error())
			}
			store := inmem.NewFromObject(dataJson)

			// Read the input from the request
			var input map[string]interface{}
			inputBytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Println("Error parsing request input: " + err.Error())
				return
			}
			err = json.Unmarshal(inputBytes, &input)
			if err != nil {
				log.Println("Error parsing input data: " + err.Error())
			}

			inputVal := input["input"] // for internal calls we have to strip off the input

			regoHandle := rego.New(
				rego.Query("data.hexaPolicy"),
				rego.Package("hexaPolicy"),
				rego.Module(regoV0path, string(regoBytes)),
				rego.Input(&inputVal),
				rego.Store(store),
				//rego.Trace(true),
			)

			resultSet, err := regoHandle.Eval(ctx)

			// Convert the internal result set to resemble opaProvider.OpaResponse
			expressionValue := resultSet[0].Expressions[0].Value.(map[string]interface{})
			if err != nil {
				log.Fatalln("Error evaluating rego: " + err.Error())
			}
			expressionValue["result"] = expressionValue["allow"]

			resBytes, _ := json.Marshal(expressionValue)
			_, _ = w.Write(resBytes)
			ctx.Done()
		}).Methods(http.MethodPost)
	}, websupport.Options{})

	go websupport.Start(server, listener)

	healthsupport.WaitForHealthy(server)
	serveUrl.Host = server.Addr
	provider.Url = serveUrl.String()
	return server
}
