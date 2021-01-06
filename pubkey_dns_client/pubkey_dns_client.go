package main

import (
    "context"
    "encoding/base32"
    "encoding/base64"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/miekg/dns"
    "golang.zx2c4.com/wireguard/wgctrl"
    "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var g_device_name = flag.String("device", "", "Wireguard device name")
var g_dns_server = flag.String("dns", "", "ip:port of DNS server")
var g_dns_zone = flag.String("zone", "", "dns zone name")
var g_peer_pubkey = flag.String("pubkey", "",
    "the public key of the specified peer")

func parse_input_args() bool {

    var result bool = false

    if 1 == len(os.Args) {
        log.Printf("missing args, try: %s --help", os.Args[0])
        return result
    }
    flag.Parse()

    if len(*g_device_name) < 1 {
        log.Println("missing device name")
        return result
    }
    if len(*g_dns_zone) < 1 {
        log.Println("missing zone")
        return result
    }
    if len(*g_dns_server) < 1 {
        log.Println("missing DNS server address")
        return result
    }
    _, _, err := net.SplitHostPort(*g_dns_server)
    if err != nil {
        log.Printf("invalid DNS server value: %v", err)
    } else {
        result = true
    }
    return result
}

func get_dns_msg(ctx context.Context, client *dns.Client,
    peer *wgtypes.Peer) (*dns.Msg, error) {

    srv_ctx, srv_cancel := context.WithCancel(ctx)

    key_base64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
    key_base32 := base32.StdEncoding.EncodeToString(peer.PublicKey[:])

    m := &dns.Msg{}

    question := fmt.Sprintf("%s._wireguard._udp.%s",
        key_base32, dns.Fqdn(*g_dns_zone))
    m.SetQuestion(question, dns.TypeSRV)

    msg, _, err := client.ExchangeContext(srv_ctx, m, *g_dns_server)
    srv_cancel()

    /* check the msg */
    if err != nil {
        return msg, fmt.Errorf("[%s] failed to lookup SRV: %v",
            key_base64, err)
    }
    if len(msg.Answer) < 1 {
        return msg, fmt.Errorf("[%s] no SRV records found", key_base64)
    }
    if len(msg.Extra) < 1 {
        log.Printf("[%s] SRV response missing extra A/AAAA", key_base64)
    }
    return msg, nil
}

func get_endpoint_ip_port(msg *dns.Msg, key string) (net.IP, int, error) {

    var endpoint_ip net.IP
    var endpoint_port int
    var err error = nil

    hostA, ok := msg.Extra[0].(*dns.A)

    if !ok {
        hostAAAA, ok := msg.Extra[0].(*dns.AAAA)
        if !ok {
            err = fmt.Errorf("[%s] non-A/AAAA extra in SRV response: %s",
                key, msg.Extra[0].String())
            return endpoint_ip, endpoint_port, err
        }
        endpoint_ip = hostAAAA.AAAA
    } else {
        endpoint_ip = hostA.A
    }
    srv, ok := msg.Answer[0].(*dns.SRV)

    if !ok {
        err = fmt.Errorf("[%s] non-SRV answer in response: %s",
            key, msg.Answer[0].String())
    }
    endpoint_port = int(srv.Port)

    return endpoint_ip, endpoint_port, err
}

func set_wireguard_peer(wg_client *wgctrl.Client,
    wg_device *wgtypes.Device,
    peer *wgtypes.Peer, msg *dns.Msg) error {

    key := base64.StdEncoding.EncodeToString(peer.PublicKey[:])

    /* If get address fails, jump out to external loop */
    ip, port, err := get_endpoint_ip_port(msg, key)

    if err != nil {
        return err
    }
    conf := wgtypes.PeerConfig{
        PublicKey:  peer.PublicKey,
        UpdateOnly: true,
        Endpoint: &net.UDPAddr{
            IP: ip, Port: port,
        },
    }
    device_conf := wgtypes.Config{
        PrivateKey:   &wg_device.PrivateKey,
        ReplacePeers: false,
        Peers:        []wgtypes.PeerConfig{conf},
    }
    if wg_device.FirewallMark > 0 {
        device_conf.FirewallMark = &wg_device.FirewallMark
    }
    err = wg_client.ConfigureDevice(*g_device_name, device_conf)

    if err != nil {
        log.Printf("[%s] failed to configure peer on %s, error: %v",
            key, *g_device_name, err)
    } else {
        log.Printf("[%s] successfully configure peer on %s",
            key, *g_device_name)
    }
    return err
}

func message_worker(ctx context.Context, done chan struct{}) {

    defer close(done)
    wg_client, err := wgctrl.New()
    if err != nil {
        log.Fatalf("error constructing Wireguard control client: %v", err)
    }
    defer wg_client.Close()

    wg_device, err := wg_client.Device(*g_device_name)
    if err != nil {
        log.Fatalf("error retrieving Wireguard device '%s' info: %v",
            *g_device_name, err)
    }
    var is_match bool = false
    dns_client := &dns.Client{Timeout: time.Second * 5}

    for _, peer := range wg_device.Peers {

        select {
        case <-ctx.Done():
            return
        default:
            break
        }

        key_base64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])

        if len(*g_peer_pubkey) > 0 && *g_peer_pubkey != key_base64 {
            continue
        } else {
            is_match = true
        }
        msg, err := get_dns_msg(ctx, dns_client, &peer)

        if err != nil {
            log.Printf("%v", err)
            continue
        }
        set_wireguard_peer(wg_client, wg_device, &peer, msg)
    }
    if !is_match {
        log.Fatalf("no peers found")
    }
}

func dns_client_run(ctx context.Context) {

    var done = make(chan struct{})

    /* launch goroutine */
    go message_worker(ctx, done)

    var sigs = make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    /* there is no default, so we'll block here until we get the signal */
    select {
    case sig := <-sigs:
        log.Printf("exiting due to signal %s", sig)
        close(done)
    case <-done: /* "message_worker" is off work already */
        break
    }
}

func main() {
    ctx, ctx_cancel := context.WithCancel(context.Background())
    /* Execute the operation before the function return */
    defer ctx_cancel()

    if true == parse_input_args() {
        dns_client_run(ctx)
    }
}
