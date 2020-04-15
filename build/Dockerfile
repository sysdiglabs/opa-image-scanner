ARG BASE_IMAGE="golang:1.14.2"

FROM ${BASE_IMAGE} as build-env

WORKDIR /go/src/app

COPY . /go/src/app
RUN go build -o /go/bin/webhook ./cmd/webhook

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env /go/bin/webhook /
ENTRYPOINT ["/webhook"]
