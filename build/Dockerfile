# syntax = docker/dockerfile:1.0-experimental
FROM golang:1.17 AS build
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -mod vendor -ldflags '-w -s' -o /app/prog -v ./cmd/main.go

#FROM migrate/migrate

#COPY ./schema /migrations

FROM alpine@sha256:d0710affa17fad5f466a70159cc458227bd25d4afb39514ef662ead3e6c99515
WORKDIR /app
COPY --from=build /app/prog .

ENTRYPOINT ["/app/prog"]
