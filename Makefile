run:
	go build -o ./build/server && ./build/server

test:
	go test ./internal/...
	go test ./pkg/...

.PHONY: run, test
