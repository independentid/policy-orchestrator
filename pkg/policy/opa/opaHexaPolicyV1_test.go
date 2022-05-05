package opaTools_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hexa-org/policy-orchestrator/pkg/websupport"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

/*
This test suite tests Hexa IDQL Support with OPA which is implemented in Rego (bundle/hexaPolicyV1.rego)
*/

const regoV1Path = "bundle/hexaPolicyV1.rego"
const dataV1Path = "bundle/bundle_test/data-V1.json"

func TestIdqlBasic(t *testing.T) {

	server := GetUpMockServer("verifyme", "")

	client := &http.Client{Timeout: time.Second * 10}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, _ := ProcessResults(results)

	assert.Contains(t, allowSet, "TestBasicCanary")

	websupport.Stop(server)

}

func TestIdqlJwt(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := GenerateBearerToken(key, "TestUser", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, _ := ProcessResults(results)

	assert.Contains(t, allowSet, "TestJwtCanary")

	websupport.Stop(server)
}

func TestIdqlIp(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(results)

	assert.Equal(t, 3, len(actionRights))
	assert.Equal(t, 1, len(allowSet))

	websupport.Stop(server)
}

/*
 This test should invoke the idql rule that permits based on IP address alone.  In the first test the URL should be
allowed as it matches one of the actions, the second should be disallowed because PUT is excluded. A third test tries
a delete which should also be refused as it is not explicitly enabled.
*/
func TestIdqlIpActions(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")

	client := &http.Client{Timeout: time.Minute * 2}

	// Test #1, Basic Auth GET request allowed by IP Address match against rule id "TestIPMaskCanary"
	fmt.Println("\nGET Test ")
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(results)

	assert.Equal(t, 6, len(actionRights))
	assert.Equal(t, 2, len(allowSet))

	//-----------------------
	// Test #2, A PUT requests that should be passed based on TeestBasicCanary match
	fmt.Println("\nPUT Test Should be allowed based on TestBasicCanary rather than TestIPCanary")
	dummy := bytes.NewBufferString("Hello world")
	req, err = http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), dummy)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")

	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ = io.ReadAll(resp.Body)
	inputStr = string(body)
	fmt.Println("input = " + inputStr)

	results = RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights = ProcessResults(results)

	assert.Equal(t, 3, len(actionRights))
	assert.Equal(t, 1, len(allowSet))

	//-----------------------
	// Test #3, A PUT requests that should be passed based on TeestBasicCanary match
	fmt.Println("\nPUT Test without Basic Auth - Should fail as PUT not allowed for TestIPMaskCanary")
	dummy = bytes.NewBufferString("Hello world")
	req, err = http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), dummy)
	if err != nil {
		assert.Error(t, err)
	}

	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ = io.ReadAll(resp.Body)
	inputStr = string(body)
	fmt.Println("input = " + inputStr)

	results = RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights = ProcessResults(results)

	assert.Equal(t, 0, len(actionRights))
	assert.Equal(t, 0, len(allowSet))

	websupport.Stop(server)
}

func TestIdqlMember(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := GenerateBearerToken(key, "JwtAlice", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(results)

	assert.Equal(t, 9, len(actionRights))
	assert.Equal(t, 3, len(allowSet))
	assert.Contains(t, allowSet, "TestJwtMember")

	websupport.Stop(server)
}

func TestIdqlRole(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key, "")
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := GenerateBearerToken(key, "BasicBob", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(body, regoV1Path, dataV1Path)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(results)

	assert.Equal(t, 11, len(actionRights))
	assert.Equal(t, 4, len(allowSet))
	assert.Contains(t, allowSet, "TestJwtRole")
	assert.Contains(t, allowSet, "TestJwtMember")

	websupport.Stop(server)
}

func RunRego(inputByte []byte, regoPath string, dataPath string) rego.ResultSet {
	ctx := context.Background()

	regoBytes, err := ioutil.ReadFile(regoPath)
	if err != nil {
		log.Fatalln("Error reading rego file: " + err.Error())
	}
	regoString := string(regoBytes)

	dataBytes, err := ioutil.ReadFile(dataPath)
	if err != nil {
		log.Fatalln("Error reading data file: " + err.Error())
	}
	var dataJson map[string]interface{}
	err = util.UnmarshalJSON(dataBytes, &dataJson)
	if err != nil {
		log.Fatalln("Error parsing data file: " + err.Error())
	}
	store := inmem.NewFromObject(dataJson)

	var input map[string]interface{}
	err = json.Unmarshal(inputByte, &input)
	if err != nil {
		log.Fatalln("Error parsing input data: " + err.Error())
	}
	regoHandle := rego.New(
		rego.Query("data.hexaPolicy"),
		rego.Package("hexaPolicy"),
		rego.Module("bundle/hexaPolicyV1.rego", regoString),
		rego.Input(&input),
		rego.Store(store),
		//rego.Trace(true),
	)

	resultSet, err := regoHandle.Eval(ctx)
	if err != nil {
		log.Fatalln("Error evaluating rego: " + err.Error())
	}

	//rego.PrintTraceWithLocation(os.Stdout, regoHandle)

	ctx.Done()

	return resultSet
}

func ProcessResults(results rego.ResultSet) ([]string, []string) {
	var rights string
	var allowString string
	result := results[0].Expressions[0]
	for k, v := range result.Value.(map[string]interface{}) {
		if k == "actionRights" {
			rights = fmt.Sprintf("%v", v)
		}
		if k == "allowSet" {
			allowString = fmt.Sprintf("%v", v)
		}
	}
	actionRights := strings.FieldsFunc(rights, func(r rune) bool {
		return strings.ContainsRune("[ ]", r)
	})
	allowSet := strings.FieldsFunc(allowString, func(r rune) bool {
		return strings.ContainsRune("[ ]", r)
	})
	fmt.Println("Text result: " + result.Text)
	fmt.Println("actionRights:" + rights)
	fmt.Println("allowSet:" + allowString)

	return allowSet, actionRights
}
