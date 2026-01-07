# protobuf version: 3.6.1
../third_party/bin/protoc --proto_path=/root/seth/src protos/*.proto --cpp_out=./
../third_party/bin/protoc --proto_path=/root/seth/src --python_out=./ protos/*.proto
