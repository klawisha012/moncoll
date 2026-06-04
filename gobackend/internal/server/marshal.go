package server

import "google.golang.org/protobuf/encoding/protojson"

func protoJSONMarshal() protojson.MarshalOptions {
	return protojson.MarshalOptions{
		UseProtoNames:   true, // snake_case JSON, matches the current API
		EmitUnpopulated: true, // emit zero values (e.g. empty containers: [])
	}
}
