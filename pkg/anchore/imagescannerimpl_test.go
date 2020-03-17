package anchore

import "testing"

func TestStartScan(t *testing.T) {
	var roundTripper *MockRoundTripper
	client := NewClient("http://mock", "mockToken")
	client.httpClient, roundTripper = getMockClient(`[{"imageDigest":"mockDigest"}]`, 200)

	digest, err := client.StartScan("mockTag")

	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	if digest != "mockDigest" {
		t.Fatalf("Wrong digest: %s", digest)
	}

	if roundTripper.RequestPath != "/images" || roundTripper.RequestMethod != "POST" {
		t.Fatalf("Unexpected request: %s %s", roundTripper.RequestMethod, roundTripper.RequestPath)
	}
}

func TestStartScanNoDigest(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`[]`, 200)

	_, err := client.StartScan("mockTag")

	if err == nil || err.Error() != "unable to obtain image digest: expected 1 image in /images response" {
		t.Fatalf("Error: %v", err)
	}
}

func TestStartScanError500(t *testing.T) {
	client := NewClient("http://mock", "mockToken")
	client.httpClient, _ = getMockClient(`[]`, 500)

	_, err := client.StartScan("mockTag")

	if err == nil || err.Error() != "unable to obtain image digest: response from Anchore: 500" {
		t.Fatalf("Error: %v", err)
	}

}

func TestIfaceGetReport(t *testing.T) {
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

	_, err := client.GetReport("mockTag", "mockDigest")

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
