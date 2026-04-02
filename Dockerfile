FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -v -o /usr/local/bin/app ./api

FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates sqlite-libs

COPY --from=builder /usr/local/bin/app .
COPY static ./static

EXPOSE 8081
CMD ["./app"]
