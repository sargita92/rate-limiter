FROM golang:1.23

RUN go install github.com/air-verse/air@latest
# RUN go install -tags 'mysql sqlite3' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

WORKDIR /go/src

COPY go.mod ./
COPY go.sum ./
RUN go mod download && go mod verify

CMD [ "air" ]