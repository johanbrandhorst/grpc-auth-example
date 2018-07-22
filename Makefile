generate:
	protoc -I proto --go_out=plugins=grpc:$$GOPATH/src/ proto/example.proto

install:
	go install ./vendor/github.com/golang/protobuf/protoc-gen-go
