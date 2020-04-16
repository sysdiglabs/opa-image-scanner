/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"k8s.io/klog"

	"image-scan-webhook/pkg/admissionserver"
	"image-scan-webhook/pkg/anchore"
	"image-scan-webhook/pkg/imagescanner"
	"image-scan-webhook/pkg/opa"
	"image-scan-webhook/pkg/opaimagescanner"
)

const opaRulesFile = "/config/rules.rego"
const policiesFile = "/config/policy.json"

var imageScanner imagescanner.Scanner
var opaEvaluator opa.OPAEvaluator

func init() {
	baseUrl := strings.TrimSpace(os.Getenv("SYSDIG_SECURE_URL"))
	if baseUrl == "" {
		panic(fmt.Errorf("Environment variable SYSDIG_SECURE_URL is not defined"))
	}

	token := strings.TrimSpace(os.Getenv("SYSDIG_SECURE_TOKEN"))
	if token == "" {
		panic(fmt.Errorf("Environment variable SYSDIG_SECURE_TOKEN is not defined"))
	}

	imageScanner = anchore.NewClient(baseUrl, token)

	opaEvaluator = opa.NewEvaluator()
}

func getOPAData() (string, error) {
	dataFileContents, err := ioutil.ReadFile(policiesFile)
	if err != nil {
		return "", err
	} else {
		return string(dataFileContents), nil
	}
}

func getOPARules() (string, error) {
	regoFileContents, err := ioutil.ReadFile(opaRulesFile)
	if err != nil {
		return "", err
	} else {
		return string(regoFileContents), nil
	}
}

func main() {
	klog.Infof("Starting AdmissionServer...")
	admissionserver.Run(opaimagescanner.NewImageScannerEvaluator(imageScanner, opaEvaluator, getOPARules, getOPAData))
	klog.Info("Exiting...")
}
