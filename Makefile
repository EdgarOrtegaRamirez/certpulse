.PHONY: build test test-race vet fmt clean install

BINARY=certpulse
CMD=./cmd/certpulse

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

test-verbose:
	go test -v ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	gofmt -l . | grep -v '^$$' && echo "Files need formatting" && exit 1 || echo "All files formatted"

clean:
	rm -f $(BINARY)
	rm -f coverage.txt

install: build
	cp $(BINARY) /usr/local/bin/

coverage:
	go test -coverprofile=coverage.txt ./...
	go tool cover -html=coverage.txt

all: vet test build
