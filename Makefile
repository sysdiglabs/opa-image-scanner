IMAGE=airadier/image-scan-webhook

all:
	go build ./...

cert: cert.crt secret.yaml

cert.crt:
	openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 3650 -out cert.crt

secret.yaml: cert.crt
	kubectl create secret generic tls --from-file=tls.crt=cert.crt --from-file=tls.key=cert.key --dry-run -o yaml > secret.yaml

run:
	./webhook --tls-cert-file cert.crt --tls-private-key-file cert.key

build-cache:
	docker build -t build-cache --target build-env -f build/Dockerfile .

docker:
	docker build --build-arg BASE_IMAGE=build-cache -t ${IMAGE} -f build/Dockerfile .

push: 
	docker push ${IMAGE}
