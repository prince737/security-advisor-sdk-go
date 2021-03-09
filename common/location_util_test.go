package common

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IBM/go-sdk-core/core"
	"github.com/stretchr/testify/assert"
)

var mockToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50Ijp7InZhbGlkIjp0cnVlLCJic3MiOiIxMjMiLCJmcm96ZW4iOnRydWV9fQ.fg7gqslY47Y5pjt5euyCUO4xqfJK1ingI84WPqC52BY"

func TestGetServiceURLSuccessFul(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-type", "application/json")
		res.WriteHeader(200)
		if req.URL.Path == "/accounts/123/settings" {
			fmt.Fprintf(res, `{
				"location": {
				  "id": "us"
				}
			  }`)
		} else {
			fmt.Fprintf(res, `{
				"si_notifications_endpoint_url": "https://us-south.secadvisor.cloud.ibm.com/notifications",
				"si_findings_endpoint_url": "",
				"id": "us"
			  }`)
		}
	}))
	AdminServiceURL = testServer.URL
	defer testServer.Close()

	a, err := GetServiceURL(core.BearerTokenAuthenticator{
		BearerToken: mockToken,
	}, "notifications_api")
	assert.Equal(t, a, "https://us-south.secadvisor.cloud.ibm.com/notifications")
	assert.Nil(t, err)
}

func TestGetServiceURLSuccessFulFindingsApi(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-type", "application/json")
		res.WriteHeader(200)
		if req.URL.Path == "/accounts/123/settings" {
			fmt.Fprintf(res, `{
				"location": {
				  "id": "us"
				}
			  }`)
		} else {
			fmt.Fprintf(res, `{
				"si_notifications_endpoint_url": "",
				"si_findings_endpoint_url": "https://us-south.secadvisor.cloud.ibm.com/findings",
				"id": "us"
			  }`)
		}
	}))
	AdminServiceURL = testServer.URL
	defer testServer.Close()

	a, err := GetServiceURL(core.BearerTokenAuthenticator{
		BearerToken: mockToken,
	}, "findings_api")
	assert.Equal(t, a, "https://us-south.secadvisor.cloud.ibm.com/findings")
	assert.Nil(t, err)
}

func TestGetServiceURLFailWhileGettingAccountSettings(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-type", "application/json")
		if req.URL.Path == "/accounts/123/settings" {
			res.WriteHeader(200)
			fmt.Fprintf(res, `{
				"location": {
				  "id": "us"
				}
			  }`)
		} else {
			res.WriteHeader(400)
			fmt.Fprintf(res, `{}`)
		}
	}))
	AdminServiceURL = testServer.URL
	defer testServer.Close()

	URL, err := GetServiceURL(core.BearerTokenAuthenticator{
		BearerToken: mockToken,
	}, "notifications_api")
	assert.Equal(t, URL, "")
	assert.EqualError(t, err, "Error while fetching location details:  Bad Request")
}

func TestGetServiceURLFailWhileGettingLocationDetails(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-type", "application/json")
		res.WriteHeader(400)
		if req.URL.Path == "/accounts/123/settings" {
			fmt.Fprintf(res, `{}`)
		}
	}))
	AdminServiceURL = testServer.URL
	defer testServer.Close()

	URL, err := GetServiceURL(core.BearerTokenAuthenticator{
		BearerToken: mockToken,
	}, "notifications_api")
	assert.Equal(t, URL, "")
	assert.EqualError(t, err, "Error while fetching location details:  Bad Request")
}

func TestVerifyLocationSuccessNotification(t *testing.T) {
	json.Unmarshal([]byte(`{
		"location": {
		  "id": "us",
		  "si_notifications_endpoint_url": "https://ss.ss",
		  "si_findings_endpoint_url": ""
		}
	  }`), &ls)
	res, err := VerifyLocation("https://ss.ss", "notifications_api")
	assert.Equal(t, res, true)
	assert.Nil(t, err)
}

func TestVerifyLocationSuccessFinding(t *testing.T) {
	json.Unmarshal([]byte(`{
		"location": {
		  "id": "us",
		  "si_notifications_endpoint_url": "",
		  "si_findings_endpoint_url": "https://ss.ss"
		}
	  }`), &ls)
	res, err := VerifyLocation("https://ss.ss", "findings_api")
	assert.Equal(t, res, true)
	assert.Nil(t, err)
}

func TestVerifyLocationSuccessURLMismatch(t *testing.T) {
	json.Unmarshal([]byte(`{
		"location": {
		  "id": "us",
		  "si_notifications_endpoint_url": "",
		  "si_findings_endpoint_url": "https://ss.ss"
		}
	  }`), &ls)
	res, err := VerifyLocation("https://ss.sssss", "findings_api")
	assert.Equal(t, res, false)
	assert.EqualError(t, err, "Service URL specified is incorrect for the selected location. Correct URL is:  https://ss.ss")
}
