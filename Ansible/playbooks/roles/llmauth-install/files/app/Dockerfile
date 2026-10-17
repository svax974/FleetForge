# llmauth — backend `auth_request` de nginx (validation des clés API).
# Construit sur l'hôte par llmauth-install (docker compose build).
FROM golang:1.23-alpine AS build

WORKDIR /src
# go.sum est OBLIGATOIRE : sans lui, `go build` refuse de résoudre les
# dépendances (« missing go.sum entry ») — l'ancienne version ne copiait que
# go.mod, dont la liste de dépendances indirectes était de surcroît absente.
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/llmauth main.go

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
# Pas de compte créé ici : l'UID d'exécution est imposé par le compose
# (`user:`), le même que celui qui possède le répertoire de données sur l'hôte.
WORKDIR /app
COPY --from=build /out/llmauth /app/llmauth
ENTRYPOINT ["/app/llmauth"]
