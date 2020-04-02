IMAGE=sysdiglabs/opa-image-scanner:local

.PHONY: build test

all: build test test-go test-rego

build:
	go build ./...

test: test-go test-rego

test-go:
	go test ./...

test-rego:
	echo "package imageadmission" > rego-test/imageadmission.rego
	echo "policies := data.policies" >> rego-test/imageadmission.rego
	echo "namespace := input.AdmissionRequest.namespace" >> rego-test/imageadmission.rego
	cat helm-charts/imageadmission.rego >> rego-test/imageadmission.rego
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

