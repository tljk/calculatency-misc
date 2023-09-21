TOOL = tls-service
GODEPS = *.go go.mod go.sum

all: test $(TOOL)

.PHONY: test
test: $(GODEPS) Makefile
	golangci-lint run
	govulncheck ./...
	go vet ./...

$(TOOL): $(GODEPS) Makefile
	go build -o $(TOOL)

.PHONY: clean
clean:
	rm -f $(TOOL)
