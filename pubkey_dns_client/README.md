# pubkey_dns_client
`pubkey_dns_client`是基于 [wgsd-client](https://github.com/jwhited/wgsd/tree/master/cmd/wgsd-client) 二次开发的客户端, 依赖装有 [pubkey_channel](https://github.com/PunkSnail/pubkey_channel) 插件的 [CoreDNS](https://github.com/coredns/coredns) 服务. 默认遍历已配置的 WireGuard peer 列表, 也可通过`-pubkey`指定单个 peer, 查询服务器上是否有匹配的公钥, 根据需要更新 peer 的配置, 运行一次即退出.

```
./pubkey_dns_client --help

Usage of ./pubkey_dns_client:
  -device string
    	name of Wireguard device to manage
  -dns string
    	ip:port of DNS server
  -zone string
    	dns zone name
  -pubkey string
        the public key of the specified peer (check all peers by default)
```

# commands_loop
`commands_loop.sh`是一个可灵活设定指定命令执行时间和次数的 shell 脚本, 这里搭配`pubkey_dns_client`使用

```
./commands_loop.sh --help
Options:
  -c '"<cmd>"'  Commands to execute, content needs to
                be enclosed in quotation marks: (\") or ('").
  -s <num>      Seconds between each execution.
  -t <num>      Variable number of loops.
  --help        Display this information.

例:
./commands_loop.sh -c '"./pubkey_dns_client -device=tunnel -dns=172.17.22.10:5300 -zone=snail -pubkey <public key>"' -s 2 -t 2

```
