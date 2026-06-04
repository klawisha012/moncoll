.PHONY: gen test build vet

gen:
	buf generate

vet:
	go vet ./...

test:
	go test ./... -count=1

build:
	CGO_ENABLED=0 go build -o bin/server ./cmd/server
