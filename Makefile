# Nome del binario finale (opzionale, serve per la build)
BINARY_NAME=main

# ==============================================================================
# 🛠️ Comandi di Sviluppo (I più usati)
# ==============================================================================

## dev: Avvia infrastruttura e applicazione (senza hot-reload)
dev: up run

## run: Esegue l'applicazione direttamente (go run)
run:
	go run cmd/api/main.go

## up: Avvia solo l'infrastruttura (DB e Redis) in background
up:
	docker compose up -d db redis

## down: Spegne e rimuove i container
down:
	docker compose down

## logs: Guarda i log dei container (DB e Redis)
logs:
	docker compose logs -f

# ==============================================================================
# 🏗️ Build & Clean
# ==============================================================================

## build: Compila il codice in un binario ottimizzato
build:
	go build -o bin/$(BINARY_NAME) cmd/api/main.go

## clean: Rimuove i file compilati
clean:
	go clean
	rm -f bin/$(BINARY_NAME)

## tidy: Pulisce e scarica le dipendenze (go mod tidy)
tidy:
	go mod tidy

# ==============================================================================
# 🧪 Testing
# ==============================================================================

## test: Esegue tutti i test
test:
	go test ./...

docs:
	 swag init -g cmd/api/main.go
# ==============================================================================
# 🚀 Help
# ==============================================================================

.PHONY: help
help: Makefile
	@echo
	@echo " Comandi disponibili nel progetto Go Auth Core:"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo