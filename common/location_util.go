package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/IBM/go-sdk-core/v3/core"
	"github.com/dgrijalva/jwt-go"
)

const defaultServiceURL = "https://us-south.secadvisor.cloud.ibm.com/notifications"

var (
	errParsing           error  = errors.New("Failed to parse token. Verify that the api key/bearer token that you specified is correct")
	errIncorrectLocation string = "Service URL specified is incorrect for the selected location. Correct URL is: "
	errFetchingLocation  string = "Error while fetching location details: "
	accountID            string
	bearerToken          string
	selectedLocationID   string
	token                string
	ls                   locationSettings
	//AdminServiceURL URL of the admin service
	AdminServiceURL string = "https://compliance.cloud.ibm.com/admin/v1"
)

type locationSettings struct {
	Location locationDetails `json:"location"`
}

type locationDetails struct {
	ID                      string `json:"id"`
	NotificationsServiceURL string `json:"si_notifications_endpoint_url"`
	FindingsServiceURL      string `json:"si_findings_endpoint_url"`
}

func makeRequest(client *http.Client, req *http.Request, token string, accountID string) (*http.Response, error) {
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func setAccountIDAndToken(Authenticator core.Authenticator) error {
	builder := core.NewRequestBuilder(core.GET)
	pathSegments := []string{}
	pathParameters := []string{}
	builder.ConstructHTTPURL(defaultServiceURL, pathSegments, pathParameters)
	request, err := builder.Build()
	if err != nil {
		return errParsing
	}

	Authenticator.Authenticate(request)
	bearerToken = request.Header.Get("Authorization")
	token = bearerToken[7:]
	parsedToken, _ := jwt.Parse(token, nil)
	if parsedToken == nil {
		return errParsing
	}
	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	accountID = claims["account"].(map[string]interface{})["bss"].(string)
	return nil
}

//GetServiceURL returns service url after verifying user current location settings
func GetServiceURL(Authenticator core.Authenticator, service string) (string, error) {
	err := setAccountIDAndToken(Authenticator)
	if err != nil {
		return "", err
	}
	location, err := getLocation()
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	// locationDetails := locationDetails{}
	req, _ := http.NewRequest("GET", AdminServiceURL+"/locations/"+location, nil)
	res, _ := makeRequest(client, req, bearerToken, accountID)
	if res.StatusCode > 399 {
		err := fmt.Errorf("%s %s", errFetchingLocation, http.StatusText(res.StatusCode))
		return "", err
	}
	json.NewDecoder(res.Body).Decode(&ls.Location)
	if service == "notifications_api" {
		return ls.Location.NotificationsServiceURL, nil
	}
	return ls.Location.FindingsServiceURL, nil
}

func getLocation() (string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", AdminServiceURL+"/accounts/"+accountID+"/settings", nil)
	res, _ := makeRequest(client, req, bearerToken, accountID)
	if res.StatusCode > 399 {
		err := fmt.Errorf("%s %s", errFetchingLocation, http.StatusText(res.StatusCode))
		return "", err
	}
	ls = locationSettings{}
	json.NewDecoder(res.Body).Decode(&ls)
	selectedLocationID = ls.Location.ID
	return selectedLocationID, nil
}

//VerifyLocation returns true if specified url is from proper location
func VerifyLocation(serviceURL string, service string) (bool, error) {
	var expectedURL string
	expectedURL = ls.Location.FindingsServiceURL
	if service == "notifications_api" {
		expectedURL = ls.Location.NotificationsServiceURL
	}
	if expectedURL != serviceURL {
		err := fmt.Errorf("%s %s", errIncorrectLocation, expectedURL)
		return false, err
	}
	return true, nil
}
