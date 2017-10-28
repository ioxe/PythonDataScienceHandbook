FROM golang:latest as builder
WORKDIR /go/src/proxy
COPY server.go .
RUN go get "github.com/yhat/wsutil"
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .


FROM alpine:latest  
USER root 
WORKDIR /root/
COPY --from=builder /go/src/proxy/server .
EXPOSE 80
CMD ["./server"]  

