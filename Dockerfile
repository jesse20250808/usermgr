FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
ARG GOPROXY=https://goproxy.io,direct
ENV GOPROXY=$GOPROXY
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/server /server
COPY admin.html ./
EXPOSE 8080
ENTRYPOINT ["/server"]
