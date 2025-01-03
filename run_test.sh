#!/bin/bash

DIR=${1:-./...}

docker exec -i rlapi go test -v $DIR -cover