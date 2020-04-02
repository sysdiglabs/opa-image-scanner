IMAGE=sysdiglabs/opa-image-scanner

.PHONY: build test

all: build test

build:
	go build ./...

test:
	go test ./...

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

