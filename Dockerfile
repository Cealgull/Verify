FROM golang:alpine
LABEL MAINTAINER toolmanp

WORKDIR /app/
COPY . /app/

RUN GOPROXY=goproxy.cn go mod tidy

RUN GOPROXY=goproxy.cn go build --ldflags "-s -w" -o "build/server"
RUN go clean -modcache -cache

CMD ["build/server"]
