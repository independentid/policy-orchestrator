package opaTools_test

import (
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
This test suite tests Hexa IDQL Support with OPA which is implemented in Rego (bundle/hexaPolicy.rego)
*/
func TestIdqlBasic(t *testing.T) {

	server := GetUpMockServer("verifyme")

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
	fmt.Println("input:\n" + inputStr)

	results := RunRego(body)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	for i := range results {
		fmt.Printf("bindings[\"x\"]: %v (i=%d)\n", results[i].Bindings["x"], i)
		fmt.Printf("value: %v (i=%d)\n", results[i].Expressions[0].Value, i)
	}
	assert.Equal(t, 1, len(results))

	result := results[0].Expressions[0]
	valueMap := result.Value.(map[string]interface{})
	var match string
	for key, value := range valueMap {
		strKey := fmt.Sprintf("%v", key)
		if strKey == "allowSet" {
			match = fmt.Sprintf("%v", value)
		}

	}

	fmt.Println("output=" + match)
	assert.Contains(t, match, "TestBasicCanary")

	websupport.Stop(server)

}

func TestIdqlJwt(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key)

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
	fmt.Println("input:\n" + inputStr)

	results := RunRego(body)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	for i := range results {
		fmt.Printf("bindings[\"x\"]: %v (i=%d)\n", results[i].Bindings["x"], i)
		fmt.Printf("value: %v (i=%d)\n", results[i].Expressions[0].Value, i)
	}

	result := results[0].Expressions[0]
	valueMap := result.Value.(map[string]interface{})
	var match string
	for key, value := range valueMap {
		strKey := fmt.Sprintf("%v", key)
		if strKey == "allowSet" {
			match = fmt.Sprintf("%v", value)
		}

	}

	fmt.Println("output=" + match)
	assert.Contains(t, match, "TestJwtCanary")

	websupport.Stop(server)
}

func TestIdqlIp(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := GetUpMockServer(key)

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
	fmt.Println("input:\n" + inputStr)

	results := RunRego(body)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	for i := range results {
		fmt.Printf("bindings[\"x\"]: %v (i=%d)\n", results[i].Bindings["x"], i)
		fmt.Printf("value: %v (i=%d)\n", results[i].Expressions[0].Value, i)
	}

	var rights string
	result := results[0].Expressions[0]
	for k, v := range result.Value.(map[string]interface{}) {
		if k == "actionRights" {
			for i := range v.([]interface{}) {
				fmt.Printf("Line %v", i)
			}
			rights = fmt.Sprintf("%v", v)
		}
	}
	actionRights := strings.FieldsFunc(rights, func(r rune) bool {
		return strings.ContainsRune("[ ]", r)
	})
	fmt.Println("Text result: " + result.Text)
	fmt.Println("Value:" + rights)
	assert.Equal(t, 3, len(actionRights))

	websupport.Stop(server)
}

func RunRego(inputByte []byte) rego.ResultSet {
	ctx := context.Background()

	regoBytes, err := ioutil.ReadFile("bundle/hexaPolicy.rego")
	if err != nil {
		log.Fatalln("Error reading rego file: " + err.Error())
	}
	regoString := string(regoBytes)

	dataBytes, err := ioutil.ReadFile("bundle/bundle_test/data.json")
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
		rego.Module("bundle/hexaPolicy.rego", regoString),
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
