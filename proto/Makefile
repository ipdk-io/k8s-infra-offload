.PHONY: all

all:
	protoc -I. --gofast_out=plugins=grpc:. ./cnibackend.proto ./felixbackend.proto ./infra.proto
