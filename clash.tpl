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

{{- $supportSet := dict "shadowsocks" true "vmess" true "vless" true "trojan" true "hysteria2" true "hysteria" true "tuic" true "anytls" true -}}
{{- $supportedProxies := list -}}
{{- range $proxy := $sorted -}}
  {{- if hasKey $supportSet $proxy.Type -}}
    {{- $supportedProxies = append $supportedProxies $proxy -}}
  {{- end -}}
{{- end -}}

# {{ .SiteName }}-{{ .SubscribeName }}
# Traffic: {{ $used }} GiB/{{ $total }} GiB | Expires: {{ $ExpiredAt }}
# Generated at: {{ now | date "2006-01-02 15:04:05" }}

mode: rule
ipv6: true
allow-lan: true
bind-address: '*'
mixed-port: 6088
log-level: error
unified-delay: true
tcp-concurrent: true
external-controller: '0.0.0.0:9090'
tun:
  enable: true
  stack: system
  auto-route: true
dns:
  enable: true
  cache-algorithm: arc
  listen: '0.0.0.0:1053'
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['*.lan', 'lens.l.google.com', '*.srv.nintendo.net', '*.stun.playstation.net', 'xbox.*.*.microsoft.com', '*.xboxlive.com', '*.msftncsi.com', '*.msftconnecttest.com']
  default-nameserver: [119.29.29.29, 223.5.5.5]
  nameserver: [system, 119.29.29.29, 223.5.5.5]
  fallback: [8.8.8.8, 1.1.1.1]
  fallback-filter: { geoip: true, geoip-code: CN }

proxies:
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

# === 以下为你要求的新分组样式 ===
proxy-groups:
  - name: 节点选择
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png
    type: select
    proxies:
      - 自动选择
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
      - DIRECT
  - name: 手动切换
    icon: https://cdn.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png
    include-all: true
    type: select
  - name: 自动选择
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png
    type: url-test
    include-all: true
    interval: 300
    tolerance: 50
  - name: 电报消息
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png
    type: select
    proxies:
      - 自动选择
      - 节点选择
      - 狮城节点
      - 香港节点
      - 台湾节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
      - DIRECT
  - name: AI平台
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bot.png
    type: select
    proxies:
      - 狮城节点
      - 台湾节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 香港节点
      - 自动选择
      - 节点选择
      - 手动切换
      - DIRECT
  - name: 油管视频
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png
    type: select
    proxies:
      - 自动选择
      - 节点选择
      - 狮城节点
      - 香港节点
      - 台湾节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
      - DIRECT
  - name: 奈飞视频
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png
    type: select
    proxies:
      - 奈飞节点
      - 自动选择
      - 节点选择
      - 狮城节点
      - 香港节点
      - 台湾节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
      - DIRECT
  - name: 巴哈姆特
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bahamut.png
    type: select
    proxies:
      - 台湾节点
      - 节点选择
      - 手动切换
      - DIRECT
  - name: 哔哩哔哩
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png
    type: select
    proxies:
      - 全球直连
      - 台湾节点
      - 香港节点
  - name: 国外媒体
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ForeignMedia.png
    type: select
    proxies:
      - 自动选择
      - 节点选择
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
      - DIRECT
  - name: 国内媒体
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/DomesticMedia.png
    type: select
    proxies:
      - DIRECT
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 手动切换
  - name: 谷歌FCM
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Google_Search.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 微软Bing
    icon: https://cdn.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/bing.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 微软云盘
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/OneDrive.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 微软服务
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png
    type: select
    proxies:
      - 自动选择
      - 节点选择
      - DIRECT
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 苹果服务
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 游戏平台
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Game.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
      - 美国节点
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 韩国节点
      - 手动切换
  - name: 网易音乐
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netease_Music.png
    type: select
    include-all: true
    filter: (?i)网易|音乐|NetEase|Music
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
  - name: 全球直连
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png
    type: select
    proxies:
      - DIRECT
      - 自动选择
      - 节点选择
  - name: 广告拦截
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png
    type: select
    proxies:
      - REJECT
      - DIRECT
  - name: 应用净化
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hijacking.png
    type: select
    proxies:
      - REJECT
      - DIRECT
  - name: 漏网之鱼
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Final.png
    type: select
    proxies:
      - 自动选择
      - 节点选择
      - DIRECT
      - 香港节点
      - 台湾节点
      - 狮城节点
      - 日本节点
      - 美国节点
      - 韩国节点
      - 手动切换
  - name: 香港节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png
    include-all: true
    filter: (?i)港|HK|hk|Hong Kong|HongKong|hongkong
    type: url-test
    interval: 300
    tolerance: 50
  - name: 日本节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png
    include-all: true
    filter: (?i)日本|川日|东京|大阪|泉日|埼玉|沪日|深日|JP|Japan
    type: url-test
    interval: 300
    tolerance: 50
  - name: 美国节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png
    include-all: true
    filter: (?i)美|波特兰|达拉斯|俄勒冈|凤凰城|费利蒙|硅谷|拉斯维加斯|洛杉矶|圣何塞|圣克拉拉|西雅图|芝加哥|US|United States
    type: url-test
    interval: 300
    tolerance: 50
  - name: 台湾节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png
    include-all: true
    filter: (?i)台|新北|彰化|TW|Taiwan
    type: url-test
    interval: 300
    tolerance: 50
  - name: 狮城节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png
    include-all: true
    filter: (?i)新加坡|坡|狮城|SG|Singapore
    type: url-test
    interval: 300
    tolerance: 50
  - name: 韩国节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Korea.png
    include-all: true
    filter: (?i)KR|Korea|KOR|首尔|韩|韓
    type: url-test
    interval: 300
    tolerance: 50
  - name: 奈飞节点
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png
    include-all: true
    filter: (?i)NF|奈飞|解锁|Netflix|NETFLIX|Media
    type: select
  - name: GLOBAL
    icon: https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png
    include-all: true
    type: url-test
    interval: 300
    tolerance: 50
    proxies:
      - 节点选择
      - 手动切换
      - 自动选择
      - 电报消息
      - AI平台
      - 油管视频
      - 奈飞视频
      - 巴哈姆特
      - 哔哩哔哩
      - 国外媒体
      - 国内媒体
      - 谷歌FCM
      - 微软Bing
      - 微软云盘
      - 微软服务
      - 苹果服务
      - 游戏平台
      - 网易音乐
      - 全球直连
      - 广告拦截
      - 应用净化
      - 漏网之鱼
      - 香港节点
      - 日本节点
      - 美国节点
      - 台湾节点
      - 狮城节点
      - 韩国节点
      - 奈飞节点

rule-providers:
  LocalAreaNetwork:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/LocalAreaNetwork.list
    path: ./ruleset/LocalAreaNetwork.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  UnBan:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/UnBan.list
    path: ./ruleset/UnBan.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  UnBan1:
    url: https://cdn.jsdelivr.net/gh/zsokami/ACL4SSR@main/UnBan1.list
    path: ./ruleset/UnBan1.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  BanAD:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanAD.list
    path: ./ruleset/BanAD.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  AdBlock:
    url: https://cdn.jsdelivr.net/gh/celin1286/ACL4SSR@main/Ruleset/AdBlock.list
    path: ./ruleset/AdBlock.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  BanProgramAD:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/BanProgramAD.list
    path: ./ruleset/BanProgramAD.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  BanProgramAD1:
    url: https://cdn.jsdelivr.net/gh/zsokami/ACL4SSR@main/BanProgramAD1.list
    path: ./ruleset/BanProgramAD1.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  GoogleFCM:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/GoogleFCM.list
    path: ./ruleset/GoogleFCM.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  GoogleCN:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/GoogleCN.list
    path: ./ruleset/GoogleCN.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  SteamCN:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/SteamCN.list
    path: ./ruleset/SteamCN.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Bing:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Bing.list
    path: ./ruleset/Bing.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  OneDrive:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/OneDrive.list
    path: ./ruleset/OneDrive.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Microsoft:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Microsoft.list
    path: ./ruleset/Microsoft.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Apple:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Apple.list
    path: ./ruleset/Apple.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Telegram:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Telegram.list
    path: ./ruleset/Telegram.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  OpenAi:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/OpenAi.list
    path: ./ruleset/OpenAi.list
    behavior: classical
    interval: 86400
    format: text
    type: http 
  AISuite:
    url: https://cdn.jsdelivr.net/gh/celin1286/ACL4SSR@main/Ruleset/AISuite.list
    path: ./ruleset/AISuite.list
    behavior: classical
    interval: 86400
    format: text
    type: http  
  NetEaseMusic:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/NetEaseMusic.list
    path: ./ruleset/NetEaseMusic.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Epic:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Epic.list
    path: ./ruleset/Epic.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Origin:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Origin.list
    path: ./ruleset/Origin.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Sony:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Sony.list
    path: ./ruleset/Sony.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Steam:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Steam.list
    path: ./ruleset/Steam.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Nintendo:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Nintendo.list
    path: ./ruleset/Nintendo.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  YouTube:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/YouTube.list
    path: ./ruleset/YouTube.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Netflix:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Netflix.list
    path: ./ruleset/Netflix.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Bahamut:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bahamut.list
    path: ./ruleset/Bahamut.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  BilibiliHMT:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/BilibiliHMT.list
    path: ./ruleset/BilibiliHMT.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  Bilibili:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/Bilibili.list
    path: ./ruleset/Bilibili.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ChinaMedia:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Ruleset/ChinaMedia.list
    path: ./ruleset/ChinaMedia.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  DirectWogg:
    url: https://down.nigx.cn/raw.githubusercontent.com/celin1286/ACL4SSR/refs/heads/main/Wogg/DirectWogg.list
    path: ./ruleset/DirectWogg.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ProxyMedia:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyMedia.list
    path: ./ruleset/ProxyMedia.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ProxyWogg:
    url: https://down.nigx.cn/raw.githubusercontent.com/celin1286/ACL4SSR/refs/heads/main/Wogg/ProxyWogg.list
    path: ./ruleset/ProxyWogg.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ProxyGFWlist:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ProxyGFWlist.list
    path: ./ruleset/ProxyGFWlist.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ChinaDomain:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaDomain.list
    path: ./ruleset/ChinaDomain.list
    behavior: domain
    interval: 86400
    format: text
    type: http
  ChinaOnly:
    url: https://cdn.jsdelivr.net/gh/zsokami/ACL4SSR@main/ChinaOnly.list
    path: ./ruleset/ChinaOnly.list
    behavior: classical
    interval: 86400
    format: text
    type: http
  ChinaCompanyIp:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/ChinaCompanyIp.list
    path: ./ruleset/ChinaCompanyIp.list
    behavior: ipcidr
    interval: 86400
    format: text
    type: http
  Download:
    url: https://cdn.jsdelivr.net/gh/ACL4SSR/ACL4SSR@master/Clash/Download.list
    path: ./ruleset/Download.list
    behavior: classical
    interval: 86400
    format: text
    type: http

rules:
  - "RULE-SET,LocalAreaNetwork,全球直连"
  - "RULE-SET,UnBan,全球直连"
  - "RULE-SET,UnBan1,全球直连"
  - "RULE-SET,BanAD,广告拦截"
  - "RULE-SET,AdBlock,广告拦截"
  - "RULE-SET,BanProgramAD,应用净化"
  - "RULE-SET,BanProgramAD1,应用净化"
  - "RULE-SET,GoogleFCM,谷歌FCM"
  - "RULE-SET,GoogleCN,全球直连"
  - "RULE-SET,SteamCN,全球直连"
  - "RULE-SET,Bing,微软Bing"
  - "RULE-SET,OneDrive,微软云盘"
  - "RULE-SET,Microsoft,微软服务"
  - "RULE-SET,Apple,苹果服务"
  - "RULE-SET,Telegram,电报消息"
  - "RULE-SET,OpenAi,AI平台"
  - "RULE-SET,AISuite,AI平台"
  - "RULE-SET,NetEaseMusic,网易音乐"
  - "RULE-SET,Epic,游戏平台"
  - "RULE-SET,Origin,游戏平台"
  - "RULE-SET,Sony,游戏平台"
  - "RULE-SET,Steam,游戏平台"
  - "RULE-SET,Nintendo,游戏平台"
  - "RULE-SET,YouTube,油管视频"
  - "RULE-SET,Netflix,奈飞视频"
  - "RULE-SET,Bahamut,巴哈姆特"
  - "RULE-SET,BilibiliHMT,哔哩哔哩"
  - "RULE-SET,Bilibili,哔哩哔哩"
  - "RULE-SET,ChinaMedia,国内媒体"
  - "RULE-SET,DirectWogg,国内媒体"
  - "RULE-SET,ProxyMedia,国外媒体"
  - "RULE-SET,ProxyWogg,国外媒体"
  - "RULE-SET,ProxyGFWlist,节点选择"
  - "RULE-SET,ChinaDomain,全球直连"
  - "RULE-SET,ChinaOnly,全球直连"
  - "RULE-SET,ChinaCompanyIp,全球直连"
  - "RULE-SET,Download,全球直连"
  - "GEOIP,CN,全球直连"
  - "MATCH,漏网之鱼"

url-rewrite:
  - ^https?:\/\/(www.)?g\.cn https://www.google.com 302
  - ^https?:\/\/(www.)?google\.cn https://www.google.com 302
