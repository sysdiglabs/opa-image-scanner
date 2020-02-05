all:
	go build ./...

cert:
	openssl req -newkey rsa:2048 -nodes -keyout cert.key -x509 -days 3650 -out cert.crt

run:
	./webhook --tls-cert-file cert.crt --tls-private-key-file cert.key

docker:
	docker build -t airadier/image-scan-webhook -f build/Dockerfile .
