FROM golang:1.22-alpine as build

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd pkg ./

ENV CGO_ENABLED=0
RUN go build -o ./sniproxy ./cmd/sniproxy/

FROM scratch

WORKDIR /

COPY --from=build /app/sniproxy /sniproxy

ENTRYPOINT [ "/sniproxy" ]
CMD [ "host", "-e", "/endpoints.txt" ]