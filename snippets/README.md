# 配置片段

这里存放了一些从 `list.yml` 中拆分出的配置片段，用于将本项目提供的一些配置整合到其它配置中。

# 文件说明

## Proxy Providers 规则集

- [nodes.yml](./nodes.yml)：节点列表，注意**不要**和下文的 `proxy.yml` 搞混了。

## Rule Providers 规则集

- [adblock.yml](./adblock.yml)：广告屏蔽域名列表。
- [proxy.yml](./proxy.yml)：需要走代理的域名列表。
- [direct.yml](./direct.yml)：需要直连的域名列表。
- [region.yml](./region.yml)：存在锁区的域名列表。

# 配置示例

```yaml
proxy-providers:
  订阅地址:
    type: http
    url: "https://ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/nodes.yml"
    interval: 3600
    path: ./proxy_providers/NoMoreWalls.yml
    health-check:
      enable: true
      interval: 600
      url: http://www.gstatic.com/generate_204

rule-providers:
  adblock:
    type: http
    behavior: classical
    path: ./rule_providers/adblock.yml
    url: "https://ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/adblock.yml"
    interval: 21600 #6h
    format: yaml
  proxy:
    type: http
    behavior: classical
    path: ./rule_providers/proxy.yml
    url: "https://ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/proxy.yml"
    interval: 86400 #24h
    format: yaml
  direct:
    type: http
    behavior: classical
    path: ./rule_providers/direct.yml
    url: "https://ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/direct.yml"
    interval: 86400 #24h
    format: yaml
  region:
    type: http
    behavior: classical
    path: ./rule_providers/region.yml
    url: "https://ghproxy.com/https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/snippets/region.yml"
    interval: 86400 #24h
    format: yaml

rules:
  - RULE-SET,adblock,⛔ 广告拦截
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,-cn,DIRECT
  - RULE-SET,region,🌐 突破锁区
  - RULE-SET,direct,DIRECT
  - GEOIP,CN,DIRECT
  - RULE-SET,proxy,🚀 选择代理
  - MATCH,🐟 漏网之鱼
```
