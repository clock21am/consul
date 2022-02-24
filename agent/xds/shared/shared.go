package shared

import (
	"github.com/golang/protobuf/proto"

	"github.com/hashicorp/consul/agent/connect"
	"github.com/hashicorp/consul/agent/proxycfg"
	"github.com/hashicorp/consul/agent/structs"
)

const (
	// Resource types in xDS v3. These are copied from
	// envoyproxy/go-control-plane/pkg/resource/v3/resource.go since we don't need any of
	// the rest of that package.
	apiTypePrefix = "type.googleapis.com/"

	// EndpointType is the TypeURL for Endpoint discovery responses.
	EndpointType = apiTypePrefix + "envoy.config.endpoint.v3.ClusterLoadAssignment"

	// ClusterType is the TypeURL for Cluster discovery responses.
	ClusterType = apiTypePrefix + "envoy.config.cluster.v3.Cluster"

	// RouteType is the TypeURL for Route discovery responses.
	RouteType = apiTypePrefix + "envoy.config.route.v3.RouteConfiguration"

	// ListenerType is the TypeURL for Listener discovery responses.
	ListenerType = apiTypePrefix + "envoy.config.listener.v3.Listener"
)

type IndexedResources struct {
	// Index is a map of typeURL => resourceName => resource
	Index map[string]map[string]proto.Message

	// ChildIndex is a map of typeURL => parentResourceName => list of
	// childResourceNames. This only applies if the child and parent do not
	// share a name.
	ChildIndex map[string]map[string][]string
}

func EmptyIndexedResources() *IndexedResources {
	return &IndexedResources{
		Index: map[string]map[string]proto.Message{
			ListenerType: make(map[string]proto.Message),
			RouteType:    make(map[string]proto.Message),
			ClusterType:  make(map[string]proto.Message),
			EndpointType: make(map[string]proto.Message),
		},
		ChildIndex: map[string]map[string][]string{
			ListenerType: make(map[string][]string),
			ClusterType:  make(map[string][]string),
		},
	}
}

type ServiceConfig struct {
	Meta map[string]string
	// the location the service is accessed from (connect-proxy or terminating-gateway).
	Kind structs.ServiceKind
}

type MutateConfiguration struct {
	ServiceConfigs   map[string]ServiceConfig
	SniToServiceName map[string]string
	Kind             structs.ServiceKind
	Datacenter       string
	TrustDomain      string
}

func MakeMutateConfiguration(cfgSnap *proxycfg.ConfigSnapshot) MutateConfiguration {
	serviceConfigs := make(map[string]ServiceConfig)
	sniMappings := make(map[string]string)

	trustDomain := ""
	if cfgSnap.Roots != nil {
		trustDomain = cfgSnap.Roots.TrustDomain
	}

	switch cfgSnap.Kind {
	case structs.ServiceKindTerminatingGateway:
		for svc, c := range cfgSnap.TerminatingGateway.ServiceConfigs {
			serviceConfigs[svc.Name] = ServiceConfig{
				Meta: c.Meta,
				Kind: structs.ServiceKindTerminatingGateway,
			}

			sni := connect.ServiceSNI(svc.Name, "", svc.NamespaceOrDefault(), svc.PartitionOrDefault(), cfgSnap.Datacenter, trustDomain)
			sniMappings[sni] = svc.Name
		}
	case structs.ServiceKindConnectProxy:
		// This is terrible. There has to be a better way to figure out where a service is running.
		kinds := make(map[string]structs.ServiceKind)
		for uid, upstreamData := range cfgSnap.ConnectProxy.WatchedUpstreamEndpoints {
			for _, serviceNodes := range upstreamData {
				for _, serviceNode := range serviceNodes {
					if serviceNode.Service.Kind == structs.ServiceKindTypical {
						kinds[uid.Name] = structs.ServiceKindConnectProxy
					} else {
						kinds[uid.Name] = serviceNode.Service.Kind
					}
				}
			}
		}

		for svc, c := range cfgSnap.ConnectProxy.ServiceConfigs {
			kind := kinds[svc.Name]
			if kind == structs.ServiceKindTypical {
				kind = structs.ServiceKindConnectProxy
			}

			serviceConfigs[svc.Name] = ServiceConfig{
				Meta: c.Meta,
				Kind: kind,
			}

			sni := connect.ServiceSNI(svc.Name, "", svc.NamespaceOrDefault(), svc.PartitionOrDefault(), cfgSnap.Datacenter, trustDomain)
			sniMappings[sni] = svc.Name
		}
	}

	return MutateConfiguration{
		ServiceConfigs:   serviceConfigs,
		SniToServiceName: sniMappings,
		Kind:             cfgSnap.Kind,
		Datacenter:       cfgSnap.Datacenter,
		TrustDomain:      trustDomain,
	}
}
