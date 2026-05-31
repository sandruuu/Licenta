FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/keycloak-scim-sync .

FROM alpine:3.21
RUN adduser -D -H -u 10001 appuser
USER appuser
COPY --from=builder /out/keycloak-scim-sync /usr/local/bin/keycloak-scim-sync
ENTRYPOINT ["/usr/local/bin/keycloak-scim-sync"]
