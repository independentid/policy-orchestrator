package microsoftazure

import (
	"fmt"
	"github.com/hexa-org/policy-orchestrator/pkg/orchestrator"
	"github.com/hexa-org/policy-orchestrator/pkg/policysupport"
	"net/http"
	"strings"
)

type AzureProvider struct {
	HttpClientOverride HTTPClient
}

func (a *AzureProvider) Name() string {
	return "azure"
}

func (a *AzureProvider) DiscoverApplications(info orchestrator.IntegrationInfo) (apps []orchestrator.ApplicationInfo, err error) {
	if !strings.EqualFold(info.Name, a.Name()) {
		return apps, err
	}

	key := info.Key
	client := a.getHttpClient()
	azureClient := AzureClient{client}
	found, _ := azureClient.GetWebApplications(key)
	apps = append(apps, found...)
	return apps, err
}

func (a *AzureProvider) GetPolicyInfo(integrationInfo orchestrator.IntegrationInfo, applicationInfo orchestrator.ApplicationInfo) ([]policysupport.PolicyInfo, error) {
	key := integrationInfo.Key
	var policies []policysupport.PolicyInfo
	client := a.getHttpClient()
	azureClient := AzureClient{client}
	principal, _ := azureClient.GetServicePrincipals(key, applicationInfo.Description) // todo - description is named poorly
	assignments, _ := azureClient.GetAppRoleAssignedTo(key, principal.List[0].ID)

	var appRoleId string
	var principalIdsAndDisplayNames []string
	var resourceIdAndDisplayName string

	for _, assignment := range assignments.List {
		appRoleId = assignment.AppRoleId
		resourceIdAndDisplayName = fmt.Sprintf("%s:%s", assignment.ResourceId, assignment.ResourceDisplayName)
		principalIdsAndDisplayNames = append(principalIdsAndDisplayNames, fmt.Sprintf("%s:%s", assignment.PrincipalId, assignment.PrincipalDisplayName))
	}

	policies = append(policies, policysupport.PolicyInfo{
		Version: "0.2",
		Action:  appRoleId,
		Subject: policysupport.SubjectInfo{AuthenticatedUsers: principalIdsAndDisplayNames},
		Object:  policysupport.ObjectInfo{Resources: []string{resourceIdAndDisplayName}},
	})

	return policies, nil
}

func (a *AzureProvider) SetPolicyInfo(integrationInfo orchestrator.IntegrationInfo, applicationInfo orchestrator.ApplicationInfo, policyInfos []policysupport.PolicyInfo) error {
	key := integrationInfo.Key
	client := a.getHttpClient()
	azureClient := AzureClient{client}
	principal, _ := azureClient.GetServicePrincipals(key, applicationInfo.Description) // todo - description is named poorly
	for _, policyInfo := range policyInfos {
		var assignments []AzureAppRoleAssignment
		resources := policyInfo.Object.Resources[0]
		for _, user := range policyInfo.Subject.AuthenticatedUsers {
			assignments = append(assignments, AzureAppRoleAssignment{
				AppRoleId:   policyInfo.Action,
				PrincipalId: strings.Split(user, ":")[0],
				ResourceId:  strings.Split(resources, ":")[0],
			})
		}
		err := azureClient.SetAppRoleAssignedTo(key, principal.List[0].ID, assignments)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *AzureProvider) getHttpClient() HTTPClient {
	if a.HttpClientOverride != nil {
		return a.HttpClientOverride
	}
	return &http.Client{}
}
