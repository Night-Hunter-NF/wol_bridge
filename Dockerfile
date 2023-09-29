# syntax=docker/dockerfile:1

FROM golang
# smoke test to verify if golang is available
RUN go version

WORKDIR /app

COPY go.mod go.sum* ./

RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /wol_bridge

CMD ["/wol_bridge"]