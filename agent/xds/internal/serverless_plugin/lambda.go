package serverless_plugin

import (
	"fmt"

	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_lambda_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/aws_lambda/v3"
	envoy_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"

	"github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	"github.com/hashicorp/consul/agent/structs"
)

type lambdaPatcher struct {
	arn                string
	payloadPassthrough bool
	region             string
	kind               structs.ServiceKind
}

func (p lambdaPatcher) patchRoute(msg proto.Message) error {
	if p.kind != structs.ServiceKindTerminatingGateway {
		return nil
	}

	route, ok := msg.(*envoy_route_v3.RouteConfiguration)
	if !ok {
		return fmt.Errorf("error decoding route")
	}
	for _, virtualHost := range route.VirtualHosts {
		for _, route := range virtualHost.Routes {
			action, ok := route.Action.(*envoy_route_v3.Route_Route)

			if !ok {
				continue
			}

			action.Route.HostRewriteSpecifier = nil
		}
	}

	return nil
}

func (p lambdaPatcher) patchCluster(msg proto.Message) (proto.Message, error) {
	c, ok := msg.(*envoy_cluster_v3.Cluster)

	if !ok {
		return msg, fmt.Errorf("error decoding cluster")
	}
	transportSocket, err := makeUpstreamTLSTransportSocket(&envoy_tls_v3.UpstreamTlsContext{
		Sni: "*.amazonaws.com",
	})

	if err != nil {
		return c, fmt.Errorf("failed to make transport socket")
	}

	cluster := &envoy_cluster_v3.Cluster{
		Name:                 c.Name,
		ConnectTimeout:       c.ConnectTimeout,
		ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{Type: envoy_cluster_v3.Cluster_LOGICAL_DNS},
		DnsLookupFamily:      envoy_cluster_v3.Cluster_V4_ONLY,
		LbPolicy:             envoy_cluster_v3.Cluster_ROUND_ROBIN,
		Metadata: &envoy_core_v3.Metadata{
			FilterMetadata: map[string]*_struct.Struct{
				"com.amazonaws.lambda": {
					Fields: map[string]*_struct.Value{
						"egress_gateway": {Kind: &_struct.Value_BoolValue{BoolValue: true}},
					},
				},
			},
		},
		LoadAssignment: &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: c.Name,
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_endpoint_v3.Endpoint{
									Address: &envoy_core_v3.Address{
										Address: &envoy_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_core_v3.SocketAddress{
												Address: fmt.Sprintf("lambda.%s.amazonaws.com", p.region),
												PortSpecifier: &envoy_core_v3.SocketAddress_PortValue{
													PortValue: 443,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		TransportSocket: transportSocket,
	}
	return cluster, nil
}

func (p lambdaPatcher) patchConnectProxyListener(msg proto.Message) (proto.Message, error) {
	l, ok := msg.(*envoy_listener_v3.Listener)

	if !ok {
		return msg, fmt.Errorf("error decoding listener")
	}

	for _, filterChain := range l.FilterChains {
		var filters []*envoy_listener_v3.Filter

		for _, filter := range filterChain.Filters {
			newFilter, _ := p.patchFilter(filter)

			filters = append(filters, newFilter)
		}
		filterChain.Filters = filters
	}

	return l, nil
}

func (p lambdaPatcher) patchFilter(filter *envoy_listener_v3.Filter) (*envoy_listener_v3.Filter, error) {
	if filter.Name != "envoy.filters.network.http_connection_manager" {
		return filter, nil
	}
	if typedConfig := filter.GetTypedConfig(); typedConfig != nil {
		config := envoy_resource_v3.GetHTTPConnectionManager(filter)
		if config == nil {
			return filter, fmt.Errorf("error unmarshaling filter.")
		}
		httpFilter, err := makeEnvoyHTTPFilter(
			"envoy.filters.http.aws_lambda",
			&envoy_lambda_v3.Config{
				Arn:                p.arn,
				PayloadPassthrough: p.payloadPassthrough,
				// TODO add invokation. Do we need to PR go-control-plane for this?
				// It looks like it is at least partially implemented there.
			},
		)
		if err != nil {
			return nil, err
		}

		config.HttpFilters = []*envoy_http_v3.HttpFilter{
			// TODO This should be more selective and replace
			// envoy.filters.http.router so it doesn't override RBAC
			httpFilter,
			{Name: "envoy.filters.http.router"},
		}
		newFilter, err := makeFilter("envoy.filters.network.http_connection_manager", config)
		if err != nil {
			return filter, fmt.Errorf("error making new filter")
		}

		return newFilter, nil
	}

	return filter, fmt.Errorf("Error getting typed config for http filter")
}
