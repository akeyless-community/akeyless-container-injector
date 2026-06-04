FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/akeyless-inject ./cmd/akeyless-inject

FROM alpine:3.21
RUN addgroup -S akeyless && adduser -S akeyless -G akeyless
COPY --from=build /out/akeyless-inject /usr/local/bin/akeyless-inject
USER akeyless
ENTRYPOINT ["/usr/local/bin/akeyless-inject"]
