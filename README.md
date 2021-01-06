# pubkey_channel
`pubkey_channel` fork 自 [wgsd](https://github.com/jwhited/wgsd/), 裁剪了部分功能, 作为 [CoreDNS](https://github.com/coredns/coredns) 的插件使用. 原项目提供了一个绝妙的点子: 把公钥当作 URL. 在 DNS 服务的基础上稍加改动就能实现两端 NAT 后主机打洞.

## build
```
git clone https://github.com/coredns/coredns.git && cd coredns
echo "pubkey_svc:github.com/punksnail/pubkey_channel" >> plugin.cfg
go generate && go build

./coredns -plugins | grep pubkey_svc # 若成功作为插件编译则输出 "dns.pubkey_svc"

# 编译 CoreDNS 后, 配置文件 Corefile 就可以添加如下配置
.:<port> {
    pubkey_svc <zone> <wg device>
}

echo -e ".:5300 {\n\tdebug\n\tpubkey_svc snail tunnel\n}" > Corefile # 为 pubkey_svc 传入分区与设备名称

```
## usage

这里的用途是 NAT hole punching, 很难简单描述, 具体参考 [WireGuard Endpoint Discovery and NAT Traversal](https://www.jordanwhited.com/posts/wireguard-endpoint-discovery-nat-traversal/)
```
Hole Punching 通信流程:

   Alice                    Punching Server                        Bob
(behind NAT)                    (global IP)                   (behind NAT)
    |                               |                               |
    |       wireguard handshake     |       wireguard handshake     |
    +------------------------------>|<------------------------------+
    |       establish tunnel        |       establish tunnel        |
    |<----------------------------->|<----------------------------->|
    |                               |                               |
    |       The server has recorded the IP:port of both peers       |
    |                               |                               |
    |                               |                               |
    |   query with Bob's public key |                               |
    +------------------------------>|                               |
    |                            wg show                            |
    |   answer Bob's IP:port    matching Bob                        |
    |<------------------------------+                               |
    |                               |                               |
 set tunnel peer                    |                               |
    |                       wireguard handshake                     |
    +-------------------------------------------------------------->|
    |                       establish tunnel                        |
    |<------------------------------------------------------------->|
    |                                                               |

补充:
    1. 在通信开始前各方都已知彼此的公钥, 以此为基础才能建立隧道
    2. Alice 与 Bob 在一开始不知道彼此的 IP:port, 但预设了隧道配置

例:
nohup ./coredns &   # Punching Server 后台运行 DNS 服务

# Alice 使用 dig 查询测试
dig @<server ip> -p <port> _wireguard._udp.snail PTR +noall +answer +additional

# Alice 编译 pubkey_dns_client 后, 通过 Bob's public key 配置隧道
./pubkey_dns_client -device=<device name> -dns=<server ip>:<port> -zone=snail -pubkey <Bob's public key>
```
