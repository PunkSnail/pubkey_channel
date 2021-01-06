package pubkey_svc

import (
    "fmt"
    "net"
    "strconv"

    "github.com/coredns/caddy"
    "github.com/coredns/coredns/core/dnsserver"
    "github.com/coredns/coredns/plugin"
    "github.com/miekg/dns"
    "golang.zx2c4.com/wireguard/wgctrl"
)

func assignment_ips(ctrl *caddy.Controller, zone *Zone) error {
    zone.serve_self = true
    args := ctrl.RemainingArgs()
    if len(args) < 1 {
        return nil
    }
    /* assume first arg is endpoint */
    addr, port_str, err := net.SplitHostPort(args[0])
    if err == nil {
        port, err := strconv.Atoi(port_str)
        if err != nil {
            return fmt.Errorf("error converting port: %v", err)
        }
        ip := net.ParseIP(addr)
        if ip == nil {
            return fmt.Errorf("invalid self endpoint address: %s", addr)
        }
        zone.self_endpoint = &net.UDPAddr{
            IP:   ip,
            Port: port,
        }
        args = args[1:]
    }
    if len(args) > 0 {
        zone.self_allowed_ips = make([]net.IPNet, 0)
    }
    for _, allowed_ips := range args {
        _, prefix, err := net.ParseCIDR(allowed_ips)
        if err != nil {
            return fmt.Errorf("invalid self allowed-ip '%s' err: %v",
                allowed_ips, err)
        }
        zone.self_allowed_ips = append(zone.self_allowed_ips, *prefix)
    }
    return nil
}

func parse(ctrl *caddy.Controller) (Zones, error) {
    zone_by_name := make(map[string]*Zone)
    names := []string{}
    res := Zones{}

    for ctrl.Next() {
        args := ctrl.RemainingArgs() // public key service zone device
        if len(args) != 2 {
            return res, fmt.Errorf("expected 2 args, got %d", len(args))
        }
        zone := &Zone{
            name:   dns.Fqdn(args[0]),
            device: args[1],
        }
        names = append(names, zone.name)
        _, ok := zone_by_name[zone.name]
        if ok {
            return res, fmt.Errorf("duplicate zone name %s", zone.name)
        }
        zone_by_name[zone.name] = zone

        for ctrl.NextBlock() {
            switch ctrl.Val() {
            case "self": // self [endpoint] [allowed-ips ... ]
                err := assignment_ips(ctrl, zone)
                if err != nil {
                    return res, err
                }
            default:
                return res, ctrl.ArgErr()
            }
        }
    }
    res.zone_by_name = zone_by_name
    res.names = names
    return res, nil
}

func setup(ctrl *caddy.Controller) error {
    zones, err := parse(ctrl)
    if err != nil {
        return plugin.Error(plugin_name, err)
    }
    client, err := wgctrl.New()
    if err != nil {
        return plugin.Error(plugin_name,
            fmt.Errorf("error constructing wgctrl client: %v", err))
    }
    ctrl.OnFinalShutdown(client.Close)

    /* Add the Plugin to CoreDNS. */
    dnsserver.GetConfig(ctrl).AddPlugin(
        func(next plugin.Handler) plugin.Handler {
            return &PubKeySvc{
                Next:   next,
                Zones:  zones,
                client: client,
            }
        })
    return nil
}

func init() {
    plugin.Register(plugin_name, setup)
}
