.PHONY: run build test vet tidy

run:
	go run ./cmd/server

build:
	go build -o bin/server ./cmd/server

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy
