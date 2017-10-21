FROM golang:latest

USER root 

COPY . /go/src/proxy

WORKDIR /go/src/proxy

RUN go get "github.com/yhat/wsutil" && go install .

ENTRYPOINT /go/bin/proxy

EXPOSE 80 443
