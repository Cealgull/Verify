FROM golang:1.20
LABEL MAINTAINER toolmanp

WORKDIR /app/
COPY . /app/

RUN go mod tidy
RUN go mod download

RUN mkdir build
RUN go build --ldflags "-s -w" -o "build/server"
RUN go clean -modcache

CMD ["./CealgullVerify"]
