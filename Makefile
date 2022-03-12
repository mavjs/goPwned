include .env
export HIBP_API_KEY

tests:
	go test -v -mod=vendor ./...

.PHONY: tests