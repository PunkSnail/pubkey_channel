package pubkey_svc

import (
    "context"
    "encoding/base32"
    "encoding/base64"
    "fmt"
    "net"
    "strings"

    "github.com/coredns/coredns/plugin"
    "github.com/coredns/coredns/plugin/pkg/log"
    "github.com/coredns/coredns/request"
    "github.com/miekg/dns"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

/* coredns plugin-specific logger */
var logger = log.NewWithPlugin(plugin_name)

const (
    plugin_name = "pubkey_svc"
)

type Zone struct {
    name             string       // the name of the zone we are authoritative for
    device           string       // the WireGuard device name
    serve_self       bool         // flag to enable serving data about self
    self_endpoint    *net.UDPAddr // overrides the self endpoint value
    self_allowed_ips []net.IPNet  // self allowed IPs
}

type Zones struct {
    /* a mapping from zone name to zone data */
    zone_by_name map[string]*Zone
    /* all keys from the map zone_by_name as a string slice */
    names []string
}

type wgctrl_client_t interface {
    Device(string) (*wgtypes.Device, error)
}

/* PubKeySvc is a CoreDNS plugin that provides WireGuard peer information
 * via DNS-SD semantics.
 *
 * PubKeySvc implements the plugin.Handler interface. */
type PubKeySvc struct {
    Next plugin.Handler
    Zones
    /* the client for retrieving WireGuard peer information */
    client wgctrl_client_t
}

const (
    /* the number of char in a base32-encoded WireGuard public key */
    key_len = 56
    /* infix of the access path */
    path_infix = "_wireguard._udp."
    /* the "+ 1" here is the character "." */
    total_path_len = key_len + len(path_infix) + 1
)

type handler_cb_t func(state request.Request,
    peers []wgtypes.Peer) (int, error)

func get_handler_cb(query_type uint16, name string) handler_cb_t {

    var result handler_cb_t = nil

    if name == path_infix && query_type == dns.TypePTR {

        result = handle_type_ptr

    } else if len(name) == total_path_len {

        if query_type == dns.TypeSRV {

            result = handle_type_srv

        } else if query_type == dns.TypeA ||
            query_type == dns.TypeAAAA || query_type == dns.TypeTXT {

            result = handle_type_txt
        }
    }
    return result
}

func handle_type_ptr(state request.Request,
    peers []wgtypes.Peer) (int, error) {
    msg := new(dns.Msg)
    msg.SetReply(state.Req)
    msg.Authoritative = true

    for _, peer := range peers {
        if peer.Endpoint == nil {
            continue
        }
        key_base32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])

        msg.Answer = append(msg.Answer, &dns.PTR{
            Hdr: dns.RR_Header{
                Name:   state.Name(),
                Rrtype: dns.TypePTR,
                Class:  dns.ClassINET,
                Ttl:    0,
            },
            Ptr: fmt.Sprintf("%s.%s%s",
                strings.ToLower(key_base32), path_infix, state.Zone),
        })
    }
    state.W.WriteMsg(msg) // nolint: errcheck
    return dns.RcodeSuccess, nil
}

func zone_to_soa(zone string) dns.RR {

    return &dns.SOA{
        Hdr: dns.RR_Header{
            Name:   zone,
            Rrtype: dns.TypeSOA,
            Class:  dns.ClassINET,
            Ttl:    60,
        },
        Ns:      fmt.Sprintf("ns1.%s", zone),
        Mbox:    fmt.Sprintf("postmaster.%s", zone),
        Serial:  1,
        Refresh: 86400,
        Retry:   7200,
        Expire:  3600000,
        Minttl:  60,
    }
}

func nx_domain(state request.Request) (int, error) {
    msg := new(dns.Msg)
    msg.SetReply(state.Req)
    msg.Authoritative = true
    msg.Rcode = dns.RcodeNameError
    msg.Ns = []dns.RR{zone_to_soa(state.Zone)}

    state.W.WriteMsg(msg) // nolint: errcheck

    return dns.RcodeSuccess, nil
}

func get_host_resource_record(name string, endpoint *net.UDPAddr) dns.RR {
    switch {
    case endpoint.IP.To4() != nil:
        return &dns.A{
            Hdr: dns.RR_Header{
                Name:   name,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET,
                Ttl:    0,
            },
            A: endpoint.IP,
        }
    case endpoint.IP.To16() != nil:
        return &dns.AAAA{
            Hdr: dns.RR_Header{
                Name:   name,
                Rrtype: dns.TypeAAAA,
                Class:  dns.ClassINET,
                Ttl:    0,
            },
            AAAA: endpoint.IP,
        }
    default:
        return nil
    }
}

func get_txt_resource_record(name string, peer wgtypes.Peer) *dns.TXT {
    var allowed_ips string
    for i, prefix := range peer.AllowedIPs {
        if i != 0 {
            allowed_ips += ","
        }
        allowed_ips += prefix.String()
    }
    key_base64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])

    /* txtvers is the first key/value pair in the TXT RR. Its serves to
     * aid clients with maintaining backwards compatibility.
     * https://tools.ietf.org/html/rfc6763#section-6.7 */
    return &dns.TXT{
        Hdr: dns.RR_Header{
            Name:   name,
            Rrtype: dns.TypeTXT,
            Class:  dns.ClassINET,
            Ttl:    0,
        },
        Txt: []string{
            fmt.Sprintf("txtvers=1"),
            fmt.Sprintf("pub=%s", key_base64),
            fmt.Sprintf("allowed=%s", allowed_ips),
        },
    }
}

func handle_type_srv(state request.Request,
    peers []wgtypes.Peer) (int, error) {
    msg := new(dns.Msg)
    msg.SetReply(state.Req)
    msg.Authoritative = true

    key := state.Name()[:key_len]

    for _, peer := range peers {
        key_base32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])

        if strings.EqualFold(key_base32, key) {
            endpoint := peer.Endpoint
            host := get_host_resource_record(state.Name(), endpoint)
            if host == nil {
                return nx_domain(state)
            }
            txt := get_txt_resource_record(state.Name(), peer)

            msg.Extra = append(msg.Extra, host, txt)
            msg.Answer = append(msg.Answer, &dns.SRV{
                Hdr: dns.RR_Header{
                    Name:   state.Name(),
                    Rrtype: dns.TypeSRV,
                    Class:  dns.ClassINET,
                    Ttl:    0,
                },
                Priority: 0,
                Weight:   0,
                Port:     uint16(endpoint.Port),
                Target:   state.Name(),
            })
            state.W.WriteMsg(msg) // nolint: errcheck
            return dns.RcodeSuccess, nil
        }
    }
    return nx_domain(state)
}

func handle_type_txt(state request.Request,
    peers []wgtypes.Peer) (int, error) {
    msg := new(dns.Msg)
    msg.SetReply(state.Req)
    msg.Authoritative = true

    key := state.Name()[:key_len]

    for _, peer := range peers {
        key_base32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])

        if strings.EqualFold(key_base32, key) {
            endpoint := peer.Endpoint

            if state.QType() == dns.TypeA ||
                state.QType() == dns.TypeAAAA {
                host := get_host_resource_record(state.Name(), endpoint)
                if host == nil {
                    return nx_domain(state)
                }
                msg.Answer = append(msg.Answer, host)
            } else {
                txt := get_txt_resource_record(state.Name(), peer)
                msg.Answer = append(msg.Answer, txt)
            }
            state.W.WriteMsg(msg) // nolint: errcheck
            return dns.RcodeSuccess, nil
        }
    }
    return nx_domain(state)
}

func get_self_peer(zone *Zone, device *wgtypes.Device,
    state request.Request) (wgtypes.Peer, error) {
    self := wgtypes.Peer{
        PublicKey: device.PublicKey,
    }
    if zone.self_endpoint != nil {
        self.Endpoint = zone.self_endpoint
    } else {
        self.Endpoint = &net.UDPAddr{
            IP:   net.ParseIP(state.LocalIP()),
            Port: device.ListenPort,
        }
    }
    self.AllowedIPs = zone.self_allowed_ips
    return self, nil
}

func get_peers(client wgctrl_client_t, zone *Zone,
    state request.Request) ([]wgtypes.Peer, error) {
    peers := make([]wgtypes.Peer, 0)

    device, err := client.Device(zone.device)
    if err != nil {
        return nil, err
    }
    peers = append(peers, device.Peers...)

    if zone.serve_self {
        self, err := get_self_peer(zone, device, state)
        if err != nil {
            return nil, err
        }
        peers = append(peers, self)
    }
    return peers, nil
}

func (svc *PubKeySvc) ServeDNS(ctx context.Context,
    w dns.ResponseWriter, msg *dns.Msg) (int, error) {
    /* packing msg and ResponseWriter. */
    state := request.Request{W: w, Req: msg}

    /* Check if the request is for a zone we are serving.
     * If it doesn't match we pass the request on to the next plugin. */
    zone_name := plugin.Zones(svc.names).Matches(state.Name())
    if zone_name == "" {
        return plugin.NextOrFailure(svc.Name(), svc.Next, ctx, w, msg)
    }
    state.Zone = zone_name

    zone, ok := svc.zone_by_name[zone_name]
    if !ok {
        return dns.RcodeServerFailure, nil
    }
    /* strip zone from name */
    name := strings.TrimSuffix(state.Name(), zone_name)
    query_type := state.QType()

    logger.Debugf("received query for: %s type: %s",
        name, dns.TypeToString[query_type])

    handler := get_handler_cb(query_type, name)
    if handler == nil {
        return nx_domain(state)
    }
    peers, err := get_peers(svc.client, zone, state)
    if err != nil {
        return dns.RcodeServerFailure, err
    }
    return handler(state, peers)
}

func (svc *PubKeySvc) Name() string {
    return plugin_name
}
