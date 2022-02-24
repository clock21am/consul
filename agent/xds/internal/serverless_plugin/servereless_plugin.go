package serverless_plugin

import (
	"fmt"
	"strings"

	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"

	"github.com/golang/protobuf/proto"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/agent/xds/shared"
)

const (
	lambdaPrefix                string = "consul-serverless-patcher.hashicorp.com/"
	LambdaEnabledTag            string = lambdaPrefix + "alpha/lambda/enabled"
	LambdaArnTag                string = lambdaPrefix + "alpha/lambda/arn"
	LambdaPayloadPassthroughTag string = lambdaPrefix + "alpha/lambda/payload-passhthrough"
	LambdaRegionTag             string = lambdaPrefix + "alpha/lambda/region"
)

func MutateIndexedResources(resources *shared.IndexedResources, config shared.MutateConfiguration) (*shared.IndexedResources, error) {
	patchers := GetPatchers(config)

	switch config.Kind {
	case structs.ServiceKindConnectProxy:
		for name, msg := range resources.Index[shared.ListenerType] {
			// TODO there has to be a better way to do this.
			serviceName := ""
			if i := strings.IndexByte(name, ':'); i != -1 {
				serviceName = name[:i]
			}

			patcher, ok := patchers[serviceName]
			if !ok {
				continue
			}

			newListener, _ := patcher.patchConnectProxyListener(msg)

			resources.Index[shared.ListenerType][name] = newListener
		}

		for sni, msg := range resources.Index[shared.ClusterType] {

			patcher, err := GetPacherBySni(config, patchers, sni)

			if err != nil {
				continue
			}

			patcher.patchCluster(msg)

			newCluster, err := patcher.patchCluster(msg)
			if err != nil {
				continue
			}

			resources.Index[shared.ClusterType][sni] = newCluster
		}
	case structs.ServiceKindTerminatingGateway:
		for sni, msg := range resources.Index[shared.ClusterType] {
			patcher, err := GetPacherBySni(config, patchers, sni)

			if err != nil {
				continue
			}

			patcher.patchCluster(msg)

			newCluster, err := patcher.patchCluster(msg)
			if err != nil {
				continue
			}

			resources.Index[shared.ClusterType][sni] = newCluster
		}

		for name, msg := range resources.Index[shared.ListenerType] {
			listener, ok := msg.(*envoy_listener_v3.Listener)

			if !ok {
				return resources, fmt.Errorf("error decoding listener")
			}

			newListener, err := patchTerminatingGatewayListener(listener, config, patchers)
			if err != nil {
				continue
			}
			resources.Index[shared.ListenerType][name] = newListener
		}

		for sni, msg := range resources.Index[shared.RouteType] {
			patcher, err := GetPacherBySni(config, patchers, sni)

			if err != nil {
				continue
			}

			patcher.patchRoute(msg)
		}
	}
	return resources, nil
}

func getSni(chain *envoy_listener_v3.FilterChain) string {
	var sni string

	if chain == nil {
		return sni
	}

	if chain.FilterChainMatch == nil {
		return sni
	}

	if len(chain.FilterChainMatch.ServerNames) == 0 {
		return sni
	}

	return chain.FilterChainMatch.ServerNames[0]
}

func patchTerminatingGatewayListener(l *envoy_listener_v3.Listener, config shared.MutateConfiguration, patchers Patchers) (proto.Message, error) {
	for _, filterChain := range l.FilterChains {
		sni := getSni(filterChain)

		patcher, err := GetPacherBySni(config, patchers, sni)

		if err != nil {
			continue
		}

		var filters []*envoy_listener_v3.Filter

		for _, filter := range filterChain.Filters {
			newFilter, _ := patcher.patchFilter(filter)

			filters = append(filters, newFilter)
		}
		filterChain.Filters = filters
	}

	return l, nil
}

type Patchers map[string]Patcher

func GetPatchers(config shared.MutateConfiguration) Patchers {
	patchers := make(Patchers)

	for name, serviceConfig := range config.ServiceConfigs {
		patcher, err := makePatcher(serviceConfig)

		if err == nil {
			patchers[name] = patcher
		}
	}

	return patchers
}

func GetPacherBySni(config shared.MutateConfiguration, patchers Patchers, name string) (Patcher, error) {
	var patcher Patcher

	serviceName, ok := config.SniToServiceName[name]

	if !ok {
		return patcher, fmt.Errorf("No sni mapping for service")
	}

	patcher, ok = patchers[serviceName]
	if !ok {
		return patcher, fmt.Errorf("No patcher for service")
	}

	return patcher, nil
}

type Patcher interface {
	patchRoute(proto.Message) error
	patchCluster(proto.Message) (proto.Message, error)
	patchConnectProxyListener(proto.Message) (proto.Message, error)
	patchFilter(*envoy_listener_v3.Filter) (*envoy_listener_v3.Filter, error)
}

func makePatcher(serviceConfig shared.ServiceConfig) (Patcher, error) {
	var patcher lambdaPatcher
	if v, ok := serviceConfig.Meta[LambdaEnabledTag]; ok && v != "" {
		arn := serviceConfig.Meta[LambdaArnTag]

		if arn == "" {
			return patcher, fmt.Errorf("arn must be populated. skipping service.")
		}

		region := serviceConfig.Meta[LambdaRegionTag]
		if region == "" {
			return patcher, fmt.Errorf("region must be populated. skipping service.")
		}
		payloadPassthroughRaw, ok := serviceConfig.Meta[LambdaPayloadPassthroughTag]
		payloadPassthrough := false
		if ok && payloadPassthroughRaw != "false" {
			payloadPassthrough = true
		}

		return lambdaPatcher{
			arn:                arn,
			payloadPassthrough: payloadPassthrough,
			region:             region,
			kind:               serviceConfig.Kind,
		}, nil
	}

	return patcher, fmt.Errorf("no patcher for service")
}
