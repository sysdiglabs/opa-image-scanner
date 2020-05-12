IMAGE=sysdiglabs/sysdig-admission-controller:local

.PHONY: build test

all: build test test-go test-rego

build:
	go build ./...

test: test-go test-rego

test-go:
	go test ./...

prepare-tests:
	echo "package prescanimageadmission" > rego-test/_generated_prescanrules.rego 
	echo "namespace := input.AdmissionRequest.namespace" >> rego-test/_generated_prescanrules.rego 
	echo "policies := data.policies" >> rego-test/_generated_prescanrules.rego
	cat helm-charts/commonrules.rego >> rego-test/_generated_prescanrules.rego
	cat helm-charts/prescanrules.rego >> rego-test/_generated_prescanrules.rego
	echo "package postscanimageadmission" > rego-test/_generated_postscanrules.rego
	echo "namespace := input.AdmissionRequest.namespace" >> rego-test/_generated_postscanrules.rego 
	echo "policies := data.policies" >> rego-test/_generated_postscanrules.rego
	cat helm-charts/commonrules.rego >> rego-test/_generated_postscanrules.rego
	cat helm-charts/postscanrules.rego >> rego-test/_generated_postscanrules.rego

test-rego: prepare-tests
	docker run --rm -v $$(pwd)/rego-test:/tests openpolicyagent/opa:0.18.0-rootless test /tests -v

cert: cert.crt secret-tls.yaml

cert.crt:
	openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 3650 -out cert.crt

secret-tls.yaml: cert.crt
	kubectl -n sysdig-image-scan create secret generic sysdig-image-scan-tls --from-file=tls.crt=cert.crt --from-file=tls.key=cert.key --dry-run -o yaml > secret-tls.yaml

run:
	./webhook --tls-cert-file cert.crt --tls-private-key-file cert.key

build-cache:
	docker build -t build-cache --target build-env -f build/Dockerfile .

docker:
	docker build --build-arg BASE_IMAGE=build-cache -t ${IMAGE} -f build/Dockerfile .

push: 
	docker push ${IMAGE}

