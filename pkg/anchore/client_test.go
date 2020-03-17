package anchore

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

type MockRoundTripper struct {
	RequestHeaders   map[string][]string
	RequestPath      string
	RequestQuery     string
	RequestBody      []byte
	RequestMethod    string
	responseString   string
	code             int
	ResponseFinished func(r *MockRoundTripper)
}

func (r *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.RequestHeaders = req.Header
	r.RequestPath = req.URL.Path
	r.RequestQuery = req.URL.RawQuery
	r.RequestMethod = req.Method
	bodyText, err := ioutil.ReadAll(req.Body)

	if err != nil {
		return nil, err
	}

	r.RequestBody = bodyText

	if r.ResponseFinished != nil {
		defer r.ResponseFinished(r)
	}

	return &http.Response{
		Status:           string(r.code),
		StatusCode:       r.code,
		Proto:            "HTTP/1.1",
		ProtoMajor:       1,
		ProtoMinor:       1,
		Header:           map[string][]string{},
		Body:             ioutil.NopCloser(strings.NewReader(r.responseString)),
		ContentLength:    int64(len(r.responseString)),
		TransferEncoding: []string{},
		Close:            true,
		Uncompressed:     true,
		Trailer:          map[string][]string{},
		Request:          req,
		TLS:              nil,
	}, nil
}

func getMockClient(response string, code int) (*http.Client, *MockRoundTripper) {

	roundTripper := &MockRoundTripper{responseString: response, code: code}
	return &http.Client{
		Transport: roundTripper,
	}, roundTripper
}

func TestAnchoreRequest(t *testing.T) {
	var roundTripper *MockRoundTripper
	client := NewClient("http://mock", "mockToken")
	client.httpClient, roundTripper = getMockClient(`Sample body`, 200)

	_, err := client.anchoreRequest("/somepath", map[string]interface{}{
		"param1": "value1", "param2": "value"}, "GET")

	if string(roundTripper.RequestBody) != `{"param1":"value1","param2":"value"}` {
		t.Fatalf("Wrong request: %s", roundTripper.RequestBody)
	}

	if string(roundTripper.RequestPath) != `/somepath` {
		t.Fatalf("Wrong path: %s", roundTripper.RequestPath)
	}

	if string(roundTripper.RequestHeaders["Authorization"][0]) != `Basic bW9ja1Rva2VuOg==` {
		t.Fatalf("Wrong auth token")
	}

	if string(roundTripper.RequestHeaders["Content-Type"][0]) != `application/json` {
		t.Fatalf("Wrong content-type")
	}

	if err != nil {
		t.Fatalf("Error: %v", err)
	}
}

func TestAnchoreRequestError(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`Sample body`, 500)

	_, err := client.anchoreRequest("/somepath", map[string]interface{}{}, "GET")

	if err == nil || err.Error() != "response from Anchore: 500" {
		t.Fatalf("Error: %v", err)
	}
}

func TestAddImage(t *testing.T) {
	var roundTripper *MockRoundTripper
	client := NewClient("http://mock", "mockToken")
	client.httpClient, roundTripper = getMockClient(`[{"imageDigest": "mockDigest"}]`, 200)

	digest, err := client.addImage("mockTag")

	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if string(roundTripper.RequestBody) != `{"tag":"mockTag"}` {
		t.Fatalf("Wrong request: %s", string(roundTripper.RequestBody))
	}

	if roundTripper.RequestMethod != "POST" {
		t.Fatalf("Wrong method: %s", roundTripper.RequestMethod)
	}

	if string(roundTripper.RequestPath) != `/images` {
		t.Fatalf("Wrong path: %s", roundTripper.RequestPath)
	}

	if digest != "mockDigest" {
		t.Fatalf("Wrong digest: %s", digest)
	}
}

func TestAddImageError(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient("", 500)

	_, err := client.addImage("mockTag")

	if err == nil || err.Error() != "response from Anchore: 500" {
		t.Fatalf("Error: %v", err)
	}
}

func TestGetReport(t *testing.T) {
	var roundTripper *MockRoundTripper
	client := NewClient("http://mock", "mockToken")
	client.httpClient, roundTripper = getMockClient(`[{
		"mockDigest" : {
			"mockTag" : [{
				"Status": "mockstatus",
				"PolicyId": "mockpolicy",
				"LastEvaluation": "ever",
				"Detail": ""
			}]
		}
	}]`, 200)

	_, err := client.getReport("mockDigest", "mockTag")

	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if string(roundTripper.RequestBody) != "" {
		t.Fatalf("Wrong request: %s", string(roundTripper.RequestBody))
	}

	if roundTripper.RequestMethod != "GET" {
		t.Fatalf("Wrong method: %s", roundTripper.RequestMethod)
	}

	if string(roundTripper.RequestPath) != `/images/mockDigest/check` {
		t.Fatalf("Wrong path: %s", roundTripper.RequestPath)
	}

	if roundTripper.RequestQuery != "tag=mockTag&history=false&detail=true" {
		t.Fatalf("Wrong query: %s", roundTripper.RequestQuery)

	}

}

func TestGetReportError(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient("", 500)

	_, err := client.GetReport("mockTag", "mockDigest")

	if err == nil || err.Error() != "unable to obtain scan report: response from Anchore: 500" {
		t.Fatalf("Error: %v", err)
	}
}

func TestGetStatusPassed(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`[{
		"mockdigest" : {
			"mockTag" : [{
				"Status": "pass",
				"PolicyId": "test",
				"LastEvaluation": "ever",
				"Detail": ""
			}]
		}
	}]`, 200)

	status, err := client.getStatus("mockdigest", "mockTag")

	if !status {
		t.Fatalf("Status is not pass")
	}

	if err != nil {
		t.Fatalf("Error: %v", err)
	}

}

func TestGetStatusFailed(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`[{
		"mockdigest" : {
			"mockTag" : [{
				"Status": "fail",
				"PolicyId": "test",
				"LastEvaluation": "ever",
				"Detail": ""
			}]
		}
	}]`, 200)

	status, err := client.getStatus("mockdigest", "mockTag")

	if status {
		t.Fatalf("Status is pass")
	}

	if err == nil || err.Error() != "Scan result is FAILED" {
		t.Fatalf("Error: %v", err)
	}

}

func TestWrongDigest(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`[{
		"wrongdigest" : {
			"mockTag" : []
		}
	}]`, 200)

	status, err := client.getStatus("mockdigest", "mockTag")

	if status {
		t.Fatalf("Status is passed")
	}

	if err == nil || err.Error() != "Digest in the scan report does not match" {
		t.Fatalf("Error: %v", err)
	}

}
