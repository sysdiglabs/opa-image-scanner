package anchore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"k8s.io/klog"

	"gopkg.in/yaml.v2"
)

var (
	transCfg = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
	}

	client = &http.Client{
		Transport: transCfg,
	}

	anchoreConfig AnchoreConfig

	anchoreConfigFile = "/tmp/sysdig-token/config.yaml"

	errNotFound = "response from Anchore: 404"
)

func init() {

	yamlFile, err := ioutil.ReadFile(anchoreConfigFile)
	if err != nil {
		klog.Errorf("[Anchore] yamlFile.Get err   #%v ", err)
	}

	err = yaml.Unmarshal(yamlFile, &anchoreConfig)
	if err != nil {
		klog.Fatalf("[Anchore] Unmarshal: %v", err)
	}
}

func anchoreRequest(path string, bodyParams map[string]string, method string) ([]byte, error) {
	username := anchoreConfig.Token
	password := ""
	anchoreEngineURL := anchoreConfig.EndpointURL
	fullURL := anchoreEngineURL + path

	bodyParamJson, err := json.Marshal(bodyParams)
	req, err := http.NewRequest(method, fullURL, bytes.NewBuffer(bodyParamJson))
	if err != nil {
		klog.Fatal(err)
	}

	req.SetBasicAuth(username, password)
	klog.Infof("[Anchore] Sending request to %s, with params %s", fullURL, bodyParams)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)

	if err != nil {
		return nil, fmt.Errorf("failed to complete request to Anchore: %v", err)
	}

	bodyText, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("failed to complete request to Anchore: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response from Anchore: %d", resp.StatusCode)
	}
	return bodyText, nil
}

func getResult(digest string, tag string) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/images/%s/check?tag=%s&history=false&detail=true", digest, tag)
	body, err := anchoreRequest(path, nil, "GET")

	if err != nil && err.Error() == errNotFound {
		// first time scanned image, return true
		klog.Warningf("[Anchore] image %s with tag %s has not been scanned.", digest, tag)
		//TODO: Report why the image is rejected
		return nil, err
	}

	if err != nil {
		klog.Errorf("[Anchore] scan error %v", err)
		//TODO: Report why the image is rejected
		return nil, err
	}

	ret := string(body)
	ret = strings.Replace(ret, "\t", "  ", -1)

	klog.Infof("[Anchore] Anchore Response Body: %s", ret)

	var result []map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		klog.Errorf("[Anchore] body unmarshall error %v", err)
		//TODO: Report why the image is rejected
		return nil, err
	}

	return result, nil
}

func getStatus(digest string, tag string) (bool, error) {
	path := fmt.Sprintf("/images/%s/check?tag=%s&history=false&detail=true", digest, tag)
	body, err := anchoreRequest(path, nil, "GET")

	if err != nil && err.Error() == errNotFound {
		// first time scanned image, return true
		klog.Warningf("[Anchore] image %s with tag %s has not been scanned.", digest, tag)
		//TODO: Report why the image is rejected
		return false, err
	}

	if err != nil {
		klog.Errorf("[Anchore] scan error %v", err)
		//TODO: Report why the image is rejected
		return false, err
	}

	ret := string(body)
	ret = strings.Replace(ret, "\t", "  ", -1)

	klog.Infof("[Anchore] Anchore Response Body: %s", ret)

	var result []map[string]map[string][]SHAResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		klog.Errorf("[Anchore] body unmarshall error %v", err)
		//TODO: Report why the image is rejected
		return false, err
	}

	foundStatus := findStatus(result)

	if strings.ToLower(foundStatus) == "pass" {
		return true, nil
	} else {
		return false, fmt.Errorf("Scan result is FAILED")
	}
}

func findStatus(parsed_result []map[string]map[string][]SHAResult) string {
	//Looks thru a parsed result for the status value, assumes this result is for a single image

	digest := reflect.ValueOf(parsed_result[0]).MapKeys()[0].String()
	tag := reflect.ValueOf(parsed_result[0][digest]).MapKeys()[0].String()
	return parsed_result[0][digest][tag][0].Status
}

func getDigest(imageRef string) (string, error) {
	// Tag or repo??
	params := map[string]string{
		"tag":     imageRef,
		"history": "true",
	}

	body, err := anchoreRequest("/images", params, "GET")
	if err != nil {
		klog.Errorf("[Anchore] %v", err)
		return "", err
	}

	var images []Image
	err = json.Unmarshal(body, &images)

	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON from response: %v", err)
	}

	return images[0].ImageDigest, nil
}

func addImage(image string) error {
	params := map[string]string{"tag": image}
	_, err := anchoreRequest("/images", params, "POST")
	if err != nil {
		return err
	}

	klog.Infof("[Anchore] Added image to Anchore Engine: %s", image)
	return nil
}

func GetImageDigest(image string) (digest string, err error) {
	err = addImage(image)
	if err != nil {
		klog.Errorf("[Anchore] addImage error: %s", err)
		return
	}

	count := 0
	for {
		digest, err = getDigest(image)
		if err == nil {
			return
		}

		klog.Errorf("[Anchore] getDigest error: %s", err)
		if count >= 5 {
			return
		}

		time.Sleep(time.Second)
		count++
	}
}

func CheckImage(image string) (bool, error) {
	digest, err := GetImageDigest(image)
	if err != nil {
		return false, fmt.Errorf("Unable to obtain image digest")
	}
	return getStatus(digest, image)
}

func GetScanResult(image string) ([]map[string]interface{}, error) {
	digest, err := GetImageDigest(image)
	if err != nil {
		return nil, fmt.Errorf("Unable to obtain image digest")
	}
	return getResult(digest, image)
}
