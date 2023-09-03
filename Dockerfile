FROM golang:alpine as build
LABEL MAINTAINER toolmanp

WORKDIR /app/
COPY . /app/

ENV CGOENABLED=1

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories
RUN apk upgrade --update-cache --available
RUN apk add build-base openssl-dev openssl && rm -rf /var/cache/apk/*

RUN GOPROXY=goproxy.cn go mod tidy
RUN GOPROXY=goproxy.cn go build --ldflags "-s -w" -o "build/server"
RUN go clean -modcache -cache

CMD ["build/server"]

FROM alpine:latest

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories
RUN apk upgrade --update-cache --available
RUN apk add openssl && rm -rf /var/cache/apk/*

COPY --from=build /app/build/server /app/server

CMD ["/app/server"]
