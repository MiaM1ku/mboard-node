package node

// Minimal independent wire adapter for sing-box's V2Ray StatsService. It uses
// official protobuf descriptors instead of importing any proxy-core runtime.
import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const statsMethod = "/v2ray.core.app.stats.command.StatsService/QueryStats"
const maxStatsReply = 32 << 20

var statsMessages = statsDescriptors()

func statsDescriptors() protoreflect.MessageDescriptors {
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, number int32, kind descriptorpb.FieldDescriptorProto_Type, many bool, typeName string) *descriptorpb.FieldDescriptorProto {
		label := optional
		if many {
			label = repeated
		}
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Type: &kind, Label: &label}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("mboard-stats.proto"), Package: proto.String("v2ray.core.app.stats.command"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("QueryStatsRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("pattern", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, false, ""),
				field("reset", 2, descriptorpb.FieldDescriptorProto_TYPE_BOOL, false, ""),
				field("patterns", 3, descriptorpb.FieldDescriptorProto_TYPE_STRING, true, ""),
				field("regexp", 4, descriptorpb.FieldDescriptorProto_TYPE_BOOL, false, ""),
			}},
			{Name: proto.String("Stat"), Field: []*descriptorpb.FieldDescriptorProto{
				field("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, false, ""),
				field("value", 2, descriptorpb.FieldDescriptorProto_TYPE_INT64, false, ""),
			}},
			{Name: proto.String("QueryStatsResponse"), Field: []*descriptorpb.FieldDescriptorProto{
				field("stat", 1, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, true, ".v2ray.core.app.stats.command.Stat"),
			}},
		},
	}, nil)
	if err != nil {
		panic(err)
	} // Static schema, independent of any remote input.
	return fd.Messages()
}

type Counter struct {
	Name  string
	Value int64
}
type StatsReader interface {
	Query(context.Context, string) ([]Counter, error)
}
type GRPCStats struct{}

func (GRPCStats) Query(ctx context.Context, address string) ([]Counter, error) {
	// No resolver, TLS downgrade, service-config retries or remote address override.
	conn, err := grpc.NewClient("passthrough:///"+address,
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDisableServiceConfig(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxStatsReply)))
	if err != nil {
		return nil, errors.New("create local stats client failed")
	}
	defer conn.Close()
	request := dynamicpb.NewMessage(statsMessages.ByName("QueryStatsRequest"))
	// Empty patterns reads each counter once. reset:false preserves closed flows
	// and avoids any destructive read before the durable journal commit.
	response := dynamicpb.NewMessage(statsMessages.ByName("QueryStatsResponse"))
	if err = conn.Invoke(ctx, statsMethod, request, response); err != nil {
		return nil, errors.New("local V2Ray stats unavailable (check core build tag, listen and timeout)")
	}
	list := response.Get(response.Descriptor().Fields().ByName("stat")).List()
	if list.Len() > 100000 {
		return nil, errors.New("too many core stats counters")
	}
	counters := make([]Counter, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		stat := list.Get(i).Message()
		counters = append(counters, Counter{Name: stat.Get(stat.Descriptor().Fields().ByName("name")).String(), Value: stat.Get(stat.Descriptor().Fields().ByName("value")).Int()})
	}
	return counters, nil
}
