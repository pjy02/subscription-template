{{- $GiB := 1073741824.0 -}}
{{- $used := printf "%.2f" (divf (add (.UserInfo.Download | default 0 | float64) (.UserInfo.Upload | default 0 | float64)) $GiB) -}}
{{- $traffic := (.UserInfo.Traffic | default 0 | float64) -}}
{{- $total := printf "%.2f" (divf $traffic $GiB) -}}

{{- $ExpiredAt := "" -}}
{{- $expStr := printf "%v" .UserInfo.ExpiredAt -}}
{{- if regexMatch `^[0-9]+$` $expStr -}}
  {{- $ts := $expStr | float64 -}}
  {{- $sec := ternary (divf $ts 1000.0) $ts (ge (len $expStr) 13) -}}
  {{- $ExpiredAt = (date "2006-01-02 15:04:05" (unixEpoch ($sec | int64))) -}}
{{- else -}}
  {{- $ExpiredAt = $expStr -}}
{{- end -}}

{{- $sortConfig := dict "Sort" "asc" -}}
{{- $byKey := dict -}}
{{- range $p := .Proxies -}}
  {{- $keyParts := list -}}
  {{- range $field, $order := $sortConfig -}}
    {{- $val := default "" (printf "%v" (index $p $field)) -}}
    {{- if or (eq $field "Sort") (eq $field "Port") -}}
      {{- $val = printf "%08d" (int (default 0 (index $p $field))) -}}
    {{- end -}}
    {{- if eq $order "desc" -}}
      {{- $val = printf "~%s" $val -}}
    {{- end -}}
    {{- $keyParts = append $keyParts $val -}}
  {{- end -}}
  {{- $_ := set $byKey (join "|" $keyParts) $p -}}
{{- end -}}
{{- $sorted := list -}}
{{- range $k := sortAlpha (keys $byKey) -}}
  {{- $sorted = append $sorted (index $byKey $k) -}}
{{- end -}}

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "anytls" true "wireguard" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

# —————————
# 基础设置
mixed-port: 7890
redir-port: 7891
tproxy-port: 1536
ipv6: true
mode: Rule
allow-lan: true
disable-keep-alive: true
geodata-mode: false
geo-auto-update: true
geo-update-interval: 24
geox-url:
  asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
experimental:
  http-headers:
    request:
      - name: "User-Agent"
        value: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36"
      - name: "Accept-Language"
        value: "en-US,en;q=0.9"
unified-delay: true
tcp-concurrent: true
log-level: silent
find-process-mode: always
global-client-fingerprint: chrome
external-controller: 0.0.0.0:9090 # 切勿修改端口会影响状态栏磁贴
external-ui-url: "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip"
external-ui: "./Web/Zash/"
secret: "" # 面板访问密码，如在公网访问建议设置
# —————————
# ==== Tips

# 1. 修改配置文件保存时，建议重启服务/重载配置.
# —————————


# 健康检查
p: &p
  type: http
  interval: 86400
  health-check:
    enable: true
    url: https://www.gstatic.com/generate_204
    interval: 300
  proxy: 订阅更新
  header: # 如遇订阅加载不出来请切换ua
      User-Agent:  # 使用注释法由上到下 默认使用第一个
        - "clash-verge/v2.2.3"
        - "ClashMetaForAndroid/2.11.2.Meta"
        - "ClashforWindows/0.19.23"
        - "clash.meta"
        - "mihomo"
# —————————


# 节点记忆
profile: # ← 此函数位置请勿变动！此为模块更新时备份恢复订阅变量范围 ↑
  store-selected: true
  store-fake-ip: true
# —————————

# 嗅探模块
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 5228, 8443]
    QUIC:
      ports: [443, 8443]
  force-domain:
    - "+.v2ex.com"
  skip-domain: # 如遇需内部通信的应用请放行该域名
    - "Mijia Cloud"
# —————————

# 网卡模块
tun:
  enable: true
  device: Meta
  stack: gvisor
  dns-hijack:
    - any:53
    - tcp://any:53
  udp-timeout: 300
  auto-route: true
  strict-route: true
  auto-redirect: false
  auto-detect-interface: true
  exclude-package: # 如黑白名单这里需排除
   # - com.tencent.mm
   # - com.tencent.mobileqq
    # _____________________# 三星专供 ↓ 范围
#    - com.samsung.android.messaging
#    - com.samsung.android.app.telephonyui
#    - com.samsung.android.dialer
#    - com.samsung.android.incallui
#    - com.samsung.android.smartcallprovider
#    - com.samsung.android.intellivoiceservice
#    - com.android.settings
#    - com.qti.qcc
#    - com.sec.epdg
#    - com.sec.imsservice # 三星专供 ↑ 范围
    # 非三星用户不必理会，三星用户需自行取消注释
# —————————


# DNS模块
# 请勿随意变动！
dns:
  enable: true
  ipv6: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip # redir-host
  fake-ip-range: 172.20.0.1/16
  fake-ip-filter:
    - "RULE-SET:Private_域"
    - "RULE-SET:GoogleFCM_域"
    - "+.3gppnetwork.org"
    - "+.xtracloud.net"
    - "+.market.xiaomi.com"
  direct-nameserver:
    - https://doh.pub/dns-query#🌐 本机·本地直连&h3=false
    - https://dns.alidns.com/dns-query#🌐 本机·本地直连&h3=true
  proxy-server-nameserver:
    - https://doh.pub/dns-query#🌐 本机·本地直连&h3=false
    - https://dns.alidns.com/dns-query#🌐 本机·本地直连&h3=true
  nameserver-policy:
    "RULE-SET:CN_域,Microsoft_域,Apple_域":
       - https://doh.pub/dns-query#🌐 本机·本地直连&h3=false
       - https://dns.alidns.com/dns-query#🌐 本机·本地直连&h3=true
  nameserver:
    - https://dns.google/dns-query#DNS连接&h3=true
    - https://cloudflare-dns.com/dns-query#DNS连接&h3=true
# —————————

A: &A
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  lazy: true
All: &All
  type: select
  include-all: true

proxies:
  - {name: 🌐 本机·本地直连, type: direct, udp: true}
  - {name: ⛔️ 禁止·拒绝连接, type: reject}
  - {name: 🌐 DNS_Hijack, type: dns}
{{- range $proxy := $supportedProxies }}
  {{- $common := "udp: true" -}}

  {{- $server := $proxy.Server -}}
  {{- if and (contains $server ":") (not (hasPrefix "[" $server)) -}}
    {{- $server = printf "[%s]" $server -}}
  {{- end -}}

  {{- $password := $.UserInfo.Password -}}
  {{- if and (eq $proxy.Type "shadowsocks") (ne (default "" $proxy.ServerKey) "") -}}
    {{- $method := $proxy.Method -}}
    {{- if or (hasPrefix "2022-blake3-" $method) (eq $method "2022-blake3-aes-128-gcm") (eq $method "2022-blake3-aes-256-gcm") -}}
      {{- $userKeyLen := ternary 16 32 (hasSuffix "128-gcm" $method) -}}
      {{- $pwdStr := printf "%s" $password -}}
      {{- $userKey := ternary $pwdStr (trunc $userKeyLen $pwdStr) (le (len $pwdStr) $userKeyLen) -}}
      {{- $serverB64 := b64enc $proxy.ServerKey -}}
      {{- $userB64 := b64enc $userKey -}}
      {{- $password = printf "%s:%s" $serverB64 $userB64 -}}
    {{- end -}}
  {{- end -}}

  {{- $SkipVerify := $proxy.AllowInsecure -}}

  {{- if eq $proxy.Type "shadowsocks" }}
  - { name: {{ $proxy.Name | quote }}, type: ss, server: {{ $server }}, port: {{ $proxy.Port }}, cipher: {{ default "aes-128-gcm" $proxy.Method }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.Obfs) "" }}, plugin: obfs, plugin-opts: { mode: {{ $proxy.Obfs }}, host: {{ default "" $proxy.ObfsHost }} }{{- end }} }
  {{- else if eq $proxy.Type "vmess" }}
  - { name: {{ $proxy.Name | quote }}, type: vmess, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, alterId: 0, cipher: auto, {{ $common }}{{- if or (eq $proxy.Transport "websocket") (eq $proxy.Transport "ws") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if or (eq $proxy.Security "tls") (eq $proxy.Security "reality") }}, tls: true{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else if eq $proxy.Type "vless" }}
  - { name: {{ $proxy.Name | quote }}, type: vless, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ $password }}, {{ $common }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "httpupgrade" }}, network: httpupgrade, httpupgrade-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }}{{- if ne (default "" $proxy.SNI) "" }}, servername: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, client-fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, tls: true, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if ne (default "" $proxy.Flow) "none" }}, flow: {{ $proxy.Flow }}{{- end }} }
  {{- else if eq $proxy.Type "trojan" }}
  - { name: {{ $proxy.Name | quote }}, type: trojan, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $SkipVerify }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }}{{- if and (eq $proxy.Security "reality") (ne (default "" $proxy.RealityPublicKey) "") }}, reality-opts: { public-key: {{ $proxy.RealityPublicKey }}{{- if ne (default "" $proxy.RealityShortId) "" }}, short-id: {{ $proxy.RealityShortId }}{{- end }} }{{- end }}{{- if or (eq $proxy.Transport "ws") (eq $proxy.Transport "websocket") }}, network: ws, ws-opts: { path: {{ default "/" $proxy.Path }}{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: {{ $proxy.Host }} }{{- end }} }{{- else if eq $proxy.Transport "http" }}, network: http, http-opts: { method: GET, path: [{{ default "/" $proxy.Path | quote }}]{{- if ne (default "" $proxy.Host) "" }}, headers: { Host: [{{ $proxy.Host | quote }}] }{{- end }} }{{- else if eq $proxy.Transport "grpc" }}, network: grpc, grpc-opts: { grpc-service-name: {{ default "grpc" $proxy.ServiceName }} }{{- end }} }
  {{- else if or (eq $proxy.Type "hysteria2") (eq $proxy.Type "hysteria") }}
  - { name: {{ $proxy.Name | quote }}, type: hysteria2, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.ObfsPassword) "" }}, obfs: salamander, obfs-password: {{ $proxy.ObfsPassword }}{{- end }}{{- if ne (default "" $proxy.HopPorts) "" }}, ports: {{ $proxy.HopPorts }}{{- end }}{{- if ne (default 0 $proxy.HopInterval) 0 }}, hop-interval: {{ $proxy.HopInterval }}{{- end }} }
  {{- else if eq $proxy.Type "tuic" }}
  - { name: {{ $proxy.Name | quote }}, type: tuic, server: {{ $server }}, port: {{ $proxy.Port }}, uuid: {{ default "" $proxy.ServerKey }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if $proxy.DisableSNI }}, disable-sni: true{{- end }}{{- if $proxy.ReduceRtt }}, reduce-rtt: true{{- end }}{{- if ne (default "" $proxy.UDPRelayMode) "" }}, udp-relay-mode: {{ $proxy.UDPRelayMode }}{{- end }}{{- if ne (default "" $proxy.CongestionController) "" }}, congestion-controller: {{ $proxy.CongestionController }}{{- end }} }
  {{- else if eq $proxy.Type "wireguard" }}
  - { name: {{ $proxy.Name | quote }}, type: wireguard, server: {{ $server }}, port: {{ $proxy.Port }}, private-key: {{ default "" $proxy.ServerKey }}, public-key: {{ default "" $proxy.RealityPublicKey }}, {{ $common }}{{- if ne (default "" $proxy.Path) "" }}, preshared-key: {{ $proxy.Path }}{{- end }}{{- if ne (default "" $proxy.RealityServerAddr) "" }}, ip: {{ $proxy.RealityServerAddr }}{{- end }}{{- if ne (default 0 $proxy.RealityServerPort) 0 }}, ipv6: {{ $proxy.RealityServerPort }}{{- end }} }
  {{- else if eq $proxy.Type "anytls" }}
  - { name: {{ $proxy.Name | quote }}, type: anytls, server: {{ $server }}, port: {{ $proxy.Port }}, password: {{ $password }}, {{ $common }}{{- if ne (default "" $proxy.SNI) "" }}, sni: {{ $proxy.SNI }}{{- end }}{{- if $proxy.AllowInsecure }}, skip-cert-verify: true{{- end }}{{- if ne (default "" $proxy.Fingerprint) "" }}, fingerprint: {{ $proxy.Fingerprint }}{{- end }} }
  {{- else }}
  - { name: {{ $proxy.Name | quote }}, type: {{ $proxy.Type }}, server: {{ $server }}, port: {{ $proxy.Port }}, {{ $common }} }
  {{- end }}
{{- end }}

{{- $allProxyNames := list -}}
{{- range $proxy := $supportedProxies -}}
  {{- $allProxyNames = append $allProxyNames $proxy.Name -}}
{{- end -}}
{{- $regionConfigs := list
  (dict "name" "ALL·香港地区" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HK.svg" "pattern" "^(?=.*(港|HK|hk|Hong Kong|HongKong|hongkong)).*$")
  (dict "name" "ALL·日本地区" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/JP.svg" "pattern" "^(?=.*(日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan)).*$")
  (dict "name" "ALL·中国台湾" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/CN.svg" "pattern" "^(?=.*(台|新北|彰化|TW|Taiwan|taipei)).*$")
  (dict "name" "ALL·美国地区" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/US.svg" "pattern" "^(?=.*(美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States)).*$")
  (dict "name" "ALL·狮城地区" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Singapore.svg" "pattern" "^(?=.*(新加坡|坡|狮城|SG|Singapore)).*$")
  (dict "name" "ALL·其它地区" "icon" "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Globe.svg" "pattern" "^(?!.*(港|HK|hk|Hong Kong|HongKong|hongkong|日本|川日|东京|大阪|泉日|埼玉|沪日|深日|[^-]日|JP|Japan|美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States|台|新北|彰化|TW|Taiwan|新加坡|坡|狮城|SG|Singapore|灾|网易|Netease|套餐|重置|剩余|到期|订阅|群|账户|流量|有效期|时间|官网|拒绝|DNS|Ch|网址|售|防失)).*$")
-}}
{{- $regionProxyMap := dict -}}
{{- range $cfg := $regionConfigs -}}
  {{- $matches := list -}}
  {{- range $proxy := $supportedProxies -}}
    {{- if regexMatch $cfg.pattern $proxy.Name -}}
      {{- $matches = append $matches $proxy.Name -}}
    {{- end -}}
  {{- end -}}
  {{- $_ := set $regionProxyMap $cfg.name $matches -}}
{{- end }}

proxy_groups: &proxy_groups
    type: select
    proxies:
      - 总模式
      - ALL·延迟最低
      - ALL·负载均衡
      - ALL·故障转移
      - ALL·香港地区
      - ALL·日本地区
      - ALL·中国台湾
      - ALL·美国地区
      - ALL·狮城地区
      - ALL·其它地区
      - ⛔️ 禁止·拒绝连接
      - 🌐 本机·本地直连
    <<: *A
# —————————
proxy-groups:
  - name: 总模式
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/All.svg"
    type: select
    proxies:
      - ALL·延迟最低
      - ALL·负载均衡
      - ALL·故障转移
      - ALL·香港地区
      - ALL·日本地区
      - ALL·中国台湾
      - ALL·美国地区
      - ALL·狮城地区
      - ALL·其它地区
      - 🌐 本机·本地直连

  - name: 订阅更新
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Update.svg"
    type: select
    proxies:
      - 🌐 本机·本地直连
      - 总模式

{{- range $cfg := $regionConfigs }}
  - name: {{ $cfg.name }}
    icon: "{{ $cfg.icon }}"
    filter: "{{ $cfg.pattern }}"
    <<: *All
    proxies:
{{- $matches := index $regionProxyMap $cfg.name }}
{{- range $matches }}
      - {{ . | quote }}
{{- end }}

{{- end }}
  - name: 小红书
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/XiaoHongShu.svg"
    <<: *proxy_groups

  - name: 抖音
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DouYin.svg"
    <<: *proxy_groups

  - name: BiliBili
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/BiliBili.svg"
    <<: *proxy_groups

  - name: Steam
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Steam.svg"
    <<: *proxy_groups

  - name: Apple
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Apple.svg"
    <<: *proxy_groups

  - name: Microsoft
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Microsoft.svg"
    <<: *proxy_groups

  - name: Telegram
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Telegram.svg"
    <<: *proxy_groups

  - name: Discord
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Discord.svg"
    <<: *proxy_groups

  - name: Spotify
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Spotify.svg"
    <<: *proxy_groups

  - name: TikTok
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/TikTok.svg"
    <<: *proxy_groups

  - name: YouTube
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/YouTube.svg"
    <<: *proxy_groups

  - name: Netflix
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Netflix.svg"
    <<: *proxy_groups

  - name: Google
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Google.svg"
    <<: *proxy_groups

  - name: GoogleFCM
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GoogleFCM.svg"
    <<: *proxy_groups

  - name: Facebook
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Facebook.svg"
    <<: *proxy_groups

  - name: OpenAI
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/OpenAI.svg"
    <<: *proxy_groups

  - name: GitHub
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/GitHub.svg"
    <<: *proxy_groups

  - name: Twitter(X)
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Twitter.svg"
    <<: *proxy_groups

  - name: DNS连接
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/DNS.svg"
    <<: *proxy_groups

  - name: 漏网之鱼
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/HBASE-copy.svg"
    <<: *proxy_groups

  - name: 广告拦截
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/No-ads-all.svg"
    type: select
    proxies:
      - REJECT-DROP
      - PASS
      - ⛔️ 禁止·拒绝连接
      - 🌐 DNS_Hijack

  - name: WebRTC
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/WebRTC.svg"
    type: select
    proxies:
      - REJECT-DROP
      - PASS
      - ⛔️ 禁止·拒绝连接
      - 🌐 DNS_Hijack

  - name: ALL·延迟最低
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: url-test
    <<: *A
    proxies:
{{- if gt (len $allProxyNames) 0 }}
{{- range $allProxyNames }}
      - {{ . | quote }}
{{- end }}
{{- else }}
      - 🌐 本机·本地直连
{{- end }}

  - name: ALL·负载均衡
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: load-balance
    strategy: round-robin
    <<: *A
    proxies:
{{- if gt (len $allProxyNames) 0 }}
{{- range $allProxyNames }}
      - {{ . | quote }}
{{- end }}
{{- else }}
      - 🌐 本机·本地直连
{{- end }}

  - name: ALL·故障转移
    icon: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/icon/Return.svg"
    type: fallback
    <<: *A
    proxies:
{{- if gt (len $allProxyNames) 0 }}
{{- range $allProxyNames }}
      - {{ . | quote }}
{{- end }}
{{- else }}
      - 🌐 本机·本地直连
{{- end }}

  - name: 特殊地址
    icon: "https://cdn.jsdelivr.net/gh/MoGuangYu/Surfing@rm/Home/icon/User.svg"
    type: select
    url: https://www.baidu.com/favicon.ico
    interval: 86400
    proxies:
      - 🌐 本机·本地直连
      - ⛔️ 禁止·拒绝连接

# —————————

rule-anchor:
  Local: &Local
    {type: file, behavior: classical, format: text}
  Classical: &Classical
    {type: http, behavior: classical, format: text, interval: 86400}
  IPCIDR: &IPCIDR
    {type: http, behavior: ipcidr, format: mrs, interval: 86400}
  Domain: &Domain
    {type: http, behavior: domain, format: mrs, interval: 86400}
# —————————

# 部分规则上游为https://github.com/blackmatrix7/ios_rule_script
# Github Actions 每日自动同步跟随更新
rule-providers:
  自定义规则: # 主要用于广告误杀自定义放行
    <<: *Local
    path: ./etc/自定义规则.list # 请按路径新建文件及建立你需要的规则

  WebRTC_端/域:
    <<: *Classical
    path: ./rules/WebRTC.list
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/Surfing@rm/Home/rules/WebRTC.list"

  CN_IP:
    <<: *IPCIDR
    path: ./rules/CN_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs"
  CN_域:
    <<: *Domain
    path: ./rules/CN_域.mrs
    url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs"

  No-ads-all_域:
    <<: *Domain
    path: ./rules/No-ads-all.mrs
    url: "https://anti-ad.net/mihomo.mrs"

  XiaoHongShu_域:
    <<: *Domain
    path: ./rules/XiaoHongShu.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/XiaoHongShu/XiaoHongShu_OCD_Domain.mrs"

  DouYin_域:
    <<: *Domain
    path: ./rules/DouYin.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/DouYin/DouYin_OCD_Domain.mrs"

  BiliBili_域:
    <<: *Domain
    path: ./rules/BiliBili.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_Domain.mrs"
  BiliBili_IP:
    <<: *IPCIDR
    path: ./rules/BiliBili_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/BiliBili/BiliBili_OCD_IP.mrs"

  Steam_域:
    <<: *Domain
    path: ./rules/Steam.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Steam/Steam_OCD_Domain.mrs"

  TikTok_域:
    <<: *Domain
    path: ./rules/TikTok.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/TikTok/TikTok_OCD_Domain.mrs"

  Spotify_域:
    <<: *Domain
    path: ./rules/Spotify.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_Domain.mrs"
  Spotify_IP:
    <<: *IPCIDR
    path: ./rules/Spotify_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Spotify/Spotify_OCD_IP.mrs"

  Facebook_域:
    <<: *Domain
    path: ./rules/Facebook.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_Domain.mrs"
  Facebook_IP:
    <<: *IPCIDR
    path: ./rules/Facebook_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Facebook/Facebook_OCD_IP.mrs"

  Telegram_域:
    <<: *Domain
    path: ./rules/Telegram.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_Domain.mrs"
  Telegram_IP:
    <<: *IPCIDR
    path: ./rules/Telegram_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Telegram/Telegram_OCD_IP.mrs"

  YouTube_域:
    <<: *Domain
    path: ./rules/YouTube.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_Domain.mrs"
  YouTube_IP:
    <<: *IPCIDR
    path: ./rules/YouTube_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/YouTube/YouTube_OCD_IP.mrs"

  Google_域:
    <<: *Domain
    path: ./rules/Google.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_Domain.mrs"
  Google_IP:
    <<: *IPCIDR
    path: ./rules/Google_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Google/Google_OCD_IP.mrs"

  GoogleFCM_域:
    <<: *Domain
    path: ./rules/GoogleFCM.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_Domain.mrs"
  GoogleFCM_IP:
    <<: *IPCIDR
    path: ./rules/GoogleFCM_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GoogleFCM/GoogleFCM_OCD_IP.mrs"

  Microsoft_域:
    <<: *Domain
    path: ./rules/Microsoft.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Microsoft/Microsoft_OCD_Domain.mrs"

  Apple_域:
    <<: *Domain
    path: ./rules/Apple.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_Domain.mrs"
  Apple_IP:
    <<: *IPCIDR
    path: ./rules/Apple_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Apple/Apple_OCD_IP.mrs"

  OpenAI_域:
    <<: *Domain
    path: ./rules/OpenAI.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_Domain.mrs"
  OpenAI_IP:
    <<: *IPCIDR
    path: ./rules/OpenAI_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/OpenAI/OpenAI_OCD_IP.mrs"

  Netflix_域:
    <<: *Domain
    path: ./rules/Netflix.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_Domain.mrs"
  Netflix_IP:
    <<: *IPCIDR
    path: ./rules/Netflix_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Netflix/Netflix_OCD_IP.mrs"

  Discord_域:
    <<: *Domain
    path: ./rules/Discord.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Discord/Discord_OCD_Domain.mrs"

  GitHub_域:
    <<: *Domain
    path: ./rules/GitHub.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/GitHub/GitHub_OCD_Domain.mrs"

  Twitter_域:
    <<: *Domain
    path: ./rules/Twitter.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_Domain.mrs"
  Twitter_IP:
    <<: *IPCIDR
    path: ./rules/Twitter_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Twitter/Twitter_OCD_IP.mrs"

  Private_域:
    <<: *Domain
    path: ./rules/LAN.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_Domain.mrs"
  Private_IP:
    <<: *IPCIDR
    path: ./rules/Private_IP.mrs
    url: "https://cdn.jsdelivr.net/gh/GitMetaio/rule@master/rule/Clash/Lan/Lan_OCD_IP.mrs"
# —————————

rules:
  - DST-PORT,53,🌐 DNS_Hijack
  - DST-PORT,853,DNS连接

  - RULE-SET,自定义规则,特殊地址

  - RULE-SET,WebRTC_端/域,WebRTC
  - RULE-SET,No-ads-all_域,广告拦截

  - PROCESS-NAME,com.ss.android.ugc.aweme,抖音
  - RULE-SET,DouYin_域,抖音

  - PROCESS-NAME,com.xingin.xhs,小红书
  - RULE-SET,XiaoHongShu_域,小红书

  - PROCESS-NAME,tv.danmaku.bili,BiliBili
  - RULE-SET,BiliBili_域,BiliBili
  - RULE-SET,BiliBili_IP,BiliBili,no-resolve

  - RULE-SET,Steam_域,Steam

  - RULE-SET,GitHub_域,GitHub

  - RULE-SET,Discord_域,Discord

  - RULE-SET,TikTok_域,TikTok

  - RULE-SET,Twitter_域,Twitter(X)
  - RULE-SET,Twitter_IP,Twitter(X),no-resolve

  - RULE-SET,YouTube_域,YouTube
  - RULE-SET,YouTube_IP,YouTube,no-resolve

  - DOMAIN-KEYWORD,mtalk.google,GoogleFCM

  - RULE-SET,Google_域,Google
  - RULE-SET,Google_IP,Google,no-resolve

  - RULE-SET,Netflix_域,Netflix
  - RULE-SET,Netflix_IP,Netflix,no-resolve

  - RULE-SET,Spotify_域,Spotify
  - RULE-SET,Spotify_IP,Spotify,no-resolve

  - RULE-SET,Facebook_域,Facebook
  - RULE-SET,Facebook_IP,Facebook,no-resolve

  - RULE-SET,OpenAI_域,OpenAI
  - RULE-SET,OpenAI_IP,OpenAI,no-resolve

  - RULE-SET,Apple_域,Apple
  - RULE-SET,Apple_IP,Apple,no-resolve

  - RULE-SET,Microsoft_域,Microsoft

  - RULE-SET,Telegram_域,Telegram
  - RULE-SET,Telegram_IP,Telegram,no-resolve

  - RULE-SET,Private_域,🌐 本机·本地直连
  - RULE-SET,Private_IP,🌐 本机·本地直连,no-resolve

  - RULE-SET,CN_域,🌐 本机·本地直连
  - RULE-SET,CN_IP,🌐 本机·本地直连

  - MATCH,漏网之鱼
# —————————
