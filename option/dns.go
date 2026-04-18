package option

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing/common/json"
)

type DNSOptions struct {
	Servers        []DNSServerOptions  `json:"servers,omitempty"`
	Rules          []DNSRule           `json:"rules,omitempty"`
	Final          string              `json:"final,omitempty"`
	ReverseMapping bool                `json:"reverse_mapping,omitempty"`
	FakeIP         *DNSFakeIPOptions   `json:"fakeip,omitempty"`
	StaticIPs      map[string][]string `json:"static_ips,omitempty"`
	DNSClientOptions
}

type DNSServerOptions struct {
	Tag                  string         `json:"tag,omitempty"`
	Address              string         `json:"address"`
	AddressResolver      string         `json:"address_resolver,omitempty"`
	AddressStrategy      DomainStrategy `json:"address_strategy,omitempty"`
	AddressFallbackDelay Duration       `json:"address_fallback_delay,omitempty"`
	Strategy             DomainStrategy `json:"strategy,omitempty"`
	Detour               string         `json:"detour,omitempty"`
	ClientSubnet         *AddrPrefix    `json:"client_subnet,omitempty"`

	// Compatibility fields for newer sing-box DNS server schema.
	Type           string `json:"type,omitempty"`
	Server         string `json:"server,omitempty"`
	ServerPort     uint16 `json:"server_port,omitempty"`
	Path           string `json:"path,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
	DomainStrategy string `json:"domain_strategy,omitempty"`
	Interface      string `json:"interface,omitempty"`
	RCode          string `json:"rcode,omitempty"`
	Code           string `json:"code,omitempty"`
	ResponseCode   string `json:"response_code,omitempty"`
}

type _DNSServerOptions DNSServerOptions

func (o *DNSServerOptions) UnmarshalJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var raw _DNSServerOptions
	if err := decoder.Decode(&raw); err != nil {
		return err
	}

	if raw.Address == "" && raw.Type != "" {
		if address, ok := typedDNSAddress(raw); ok {
			raw.Address = address
		}
	}
	if raw.AddressResolver == "" && raw.DomainResolver != "" {
		raw.AddressResolver = raw.DomainResolver
	}
	if raw.AddressStrategy == DomainStrategy(0) && raw.DomainStrategy != "" {
		var strategy DomainStrategy
		if err := strategy.UnmarshalJSON([]byte(`"` + raw.DomainStrategy + `"`)); err == nil {
			raw.AddressStrategy = strategy
		}
	}

	*o = DNSServerOptions(raw)
	return nil
}

type DNSClientOptions struct {
	Strategy         DomainStrategy `json:"strategy,omitempty"`
	DisableCache     bool           `json:"disable_cache,omitempty"`
	DisableExpire    bool           `json:"disable_expire,omitempty"`
	IndependentCache bool           `json:"independent_cache,omitempty"`
	ClientSubnet     *AddrPrefix    `json:"client_subnet,omitempty"`
}

type DNSFakeIPOptions struct {
	Enabled    bool          `json:"enabled,omitempty"`
	Inet4Range *netip.Prefix `json:"inet4_range,omitempty"`
	Inet6Range *netip.Prefix `json:"inet6_range,omitempty"`
}

func typedDNSAddress(o _DNSServerOptions) (string, bool) {
	dnsType := strings.ToLower(strings.TrimSpace(o.Type))
	host := strings.TrimSpace(o.Server)
	port := int(o.ServerPort)
	path := strings.TrimSpace(o.Path)

	switch dnsType {
	case "local":
		return "local", true
	case "fakeip":
		return "fakeip", true
	case "dhcp":
		iface := strings.TrimSpace(o.Interface)
		if iface == "" {
			iface = "auto"
		}
		return "dhcp://" + iface, true
	case "rcode":
		code := strings.TrimSpace(o.RCode)
		if code == "" {
			code = strings.TrimSpace(o.Code)
		}
		if code == "" {
			code = strings.TrimSpace(o.ResponseCode)
		}
		if code == "" {
			code = "refused"
		}
		return "rcode://" + code, true
	case "udp":
		if host == "" {
			return "", false
		}
		return formatLegacyAddressHost(host, port, 53), true
	case "tcp":
		if host == "" {
			return "", false
		}
		return "tcp://" + formatLegacyAddressHost(host, port, 53), true
	case "tls":
		if host == "" {
			return "", false
		}
		return "tls://" + formatLegacyAddressHost(host, port, 853), true
	case "https":
		if host == "" {
			return "", false
		}
		return "https://" + formatLegacyAddressHost(host, port, 443) + normalizeDNSPath(path), true
	case "h3", "http3":
		if host == "" {
			return "", false
		}
		return "h3://" + formatLegacyAddressHost(host, port, 443) + normalizeDNSPath(path), true
	case "quic":
		if host == "" {
			return "", false
		}
		return "quic://" + formatLegacyAddressHost(host, port, 853), true
	default:
		return "", false
	}
}

func normalizeDNSPath(path string) string {
	if path == "" {
		return "/dns-query"
	}
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func formatLegacyAddressHost(host string, port int, defaultPort int) string {
	if host == "" {
		return ""
	}
	if hasLegacyExplicitPort(host) {
		return host
	}
	if port <= 0 {
		port = defaultPort
	}
	if port == defaultPort {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func hasLegacyExplicitPort(host string) bool {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return true
	}
	if strings.Count(host, ":") == 1 && !strings.Contains(host, "]") {
		parts := strings.Split(host, ":")
		if len(parts) == 2 {
			_, err := strconv.Atoi(parts[1])
			return err == nil
		}
	}
	return false
}
