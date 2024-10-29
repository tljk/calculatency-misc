binary = client
godeps = *.go go.mod go.sum

.PHONY: all
all: lint $(binary)

.PHONY: lint
lint:
	golangci-lint run

$(binary): $(godeps)
	go build -o $(binary)

.PHONY: clean
clean:
	rm -f $(binary)
