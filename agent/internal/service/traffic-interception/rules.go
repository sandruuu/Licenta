package trafficinterception

import (
	"fmt"
	"net"
	"sort"
	"strings"

	wfpcontrol "agent/internal/service/wfp-control"
)

type route struct {
	ResourceID        string
	FQDN              string
	Protocol          string
	TransportProtocol string
	Port              int
	SyntheticIP       string
}

type routeTable struct {
	byDestination map[string]route
	routes        []route
}

func newRouteTable(mappings []ResourceMapping) (routeTable, []wfpcontrol.Rule, error) {
	routes := make([]route, 0, len(mappings))
	seen := make(map[string]route, len(mappings))
	for _, mapping := range mappings {
		normalized, err := normalizeRoute(mapping)
		if err != nil {
			return routeTable{}, nil, err
		}
		if normalized.TransportProtocol != "tcp" {
			continue
		}
		key := routeKey(normalized.SyntheticIP, normalized.Port, normalized.TransportProtocol)
		seen[key] = normalized
	}
	for _, value := range seen {
		routes = append(routes, value)
	}
	sort.Slice(routes, func(left, right int) bool {
		if routes[left].SyntheticIP == routes[right].SyntheticIP {
			return routes[left].Port < routes[right].Port
		}
		return routes[left].SyntheticIP < routes[right].SyntheticIP
	})
	table := routeTable{byDestination: make(map[string]route, len(routes)), routes: routes}
	rules := make([]wfpcontrol.Rule, 0, len(routes))
	for _, item := range routes {
		table.byDestination[routeKey(item.SyntheticIP, item.Port, item.TransportProtocol)] = item
		rules = append(rules, wfpcontrol.Rule{
			SyntheticIP: item.SyntheticIP,
			Port:        item.Port,
			Protocol:    item.TransportProtocol,
		})
	}
	return table, rules, nil
}

func (table routeTable) Lookup(ip string, port int, protocol string) (route, bool) {
	if len(table.byDestination) == 0 {
		return route{}, false
	}
	if item, ok := table.byDestination[routeKey(ip, port, protocol)]; ok {
		return item, true
	}
	item, ok := table.byDestination[routeKey(ip, 0, protocol)]
	return item, ok
}

func (table routeTable) Len() int {
	return len(table.routes)
}

func normalizeRoute(mapping ResourceMapping) (route, error) {
	ip := net.ParseIP(strings.TrimSpace(mapping.SyntheticIP)).To4()
	if ip == nil {
		return route{}, fmt.Errorf("synthetic IP %q is not an IPv4 address", mapping.SyntheticIP)
	}
	port := mapping.Port
	if port < 0 || port > 65535 {
		return route{}, fmt.Errorf("resource %q port %d is outside TCP/UDP range", mapping.ResourceID, mapping.Port)
	}
	protocol := strings.ToLower(strings.TrimSpace(mapping.Protocol))
	transportProtocol := protocol
	switch protocol {
	case "":
		protocol = "tcp"
		transportProtocol = "tcp"
	case "http", "https", "rdp", "ssh", "tcp":
		transportProtocol = "tcp"
	case "udp":
		transportProtocol = "udp"
	default:
		return route{}, fmt.Errorf("resource %q uses unsupported interception protocol %q", mapping.ResourceID, mapping.Protocol)
	}
	return route{
		ResourceID:        strings.TrimSpace(mapping.ResourceID),
		FQDN:              strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapping.FQDN), ".")),
		Protocol:          protocol,
		TransportProtocol: transportProtocol,
		Port:              port,
		SyntheticIP:       ip.String(),
	}, nil
}

func routeKey(ip string, port int, protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol)) + "|" + strings.TrimSpace(ip) + "|" + fmt.Sprint(port)
}
