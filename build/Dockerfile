FROM golang:1.13.4 as build-env

WORKDIR /go/src/app
ADD . /go/src/app

RUN go get -d -v ./...

RUN go build -o /go/bin/webhook ./cmd/webhook

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env /go/bin/webhook /
ENTRYPOINT ["/webhook"]
