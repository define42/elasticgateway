all:
	docker compose build
run:
	docker compose stop
	docker compose build
	docker compose up
test:
	go test ./... -coverpkg=./... -cover

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

