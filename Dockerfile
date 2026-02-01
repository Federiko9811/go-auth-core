# --------------------------------------------------------
# STAGE 1: Build
# Usiamo l'immagine ufficiale di Go per compilare
# --------------------------------------------------------
FROM golang:1.22-alpine AS builder

# Installiamo git (spesso serve per scaricare dipendenze)
RUN apk add --no-cache git

# Impostiamo la directory di lavoro
WORKDIR /app

# Copiamo i file di definizione delle dipendenze
# Lo facciamo PRIMA di copiare tutto il codice per sfruttare la cache di Docker
COPY go.mod go.sum ./
RUN go mod download

# Copiamo il resto del codice sorgente
COPY . .

# Compiliamo l'applicazione
# -o main: nome dell'output
# cmd/api/main.go: il file da compilare
RUN go build -o main cmd/api/main.go

# --------------------------------------------------------
# STAGE 2: Run
# Usiamo un'immagine piccolissima (Alpine) solo per eseguire
# --------------------------------------------------------
FROM alpine:latest

WORKDIR /root/

# Copiamo SOLO il file binario compilato dallo stage precedente (builder)
COPY --from=builder /app/main .

# Copiamo il file .env (opzionale: in prod vero useresti le env del container)
COPY .env .

# Esponiamo la porta
EXPOSE 8080

# Comando di avvio
CMD ["./main"]