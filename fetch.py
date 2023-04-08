#!/usr/bin/env python3
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
import datetime
import traceback
import binascii
from dynamic import AUTOURLS, AUTOFETCH, set_dynamic_globals

try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else: LOCAL = not PROXY

def b64encodes(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def b64decodes_safe(s):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id', 
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_EXAMPLE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": '8'*8+'-8888'*3+'-'+'8'*12
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none"
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305"
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth"
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b"

class UnsupportedType(Exception): pass

class Node:
    def __init__(self, data):
        if isinstance(data, dict):
            self.data = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else: raise TypeError
        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])

    def __str__(self):
        return self.url

    def __hash__(self):
        return hash(f"{self.data['server']}:{self.data['port']}")
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    def load_url(self, url):
        self.type = url.split("://")[0]
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        # === Fix end ===
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            try: v.update(json.loads(b64decodes(url[8:])))
            except Exception:
                raise UnsupportedType('vmess', 'SP')
            self.data = {}
            for key, val in v.items():
                if key in VMESS2CLASH:
                    self.data[VMESS2CLASH[key]] = val
            self.data['tls'] = (v['tls'] == 'tls')
            self.data['alterId'] = int(self.data['alterId'])
            if v['net'] == 'ws':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['headers'] = {'Host': v['host']}
                self.data['ws-opts'] = opts

        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            if '#' in srvname:
                srv, name = srvname.split('#')
            else:
                srv = srvname
                name = ''
            server, port = srv.split(':')
            try:
                port = int(port)
            except ValueError:
                raise UnsupportedType('ss', 'SP')
            info = '@'.join(info)
            if not ':' in info:
                info = b64decodes_safe(info)
            if ':' in info:
                cipher, passwd = info.split(':')
            else:
                cipher = info
                passwd = ''
            self.data = {'name': unquote(name), 'server': server, 
                    'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

        elif self.type == 'ssr':
            if '?' in url:
                parts = url[6:].split(':')
            else:
                parts = b64decodes_safe(url[6:]).split(':')
            try:
                passwd, info = parts[-1].split('/?')
            except: raise
            passwd = b64decodes_safe(passwd)
            self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                    'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                    'password': passwd, 'name': ''}
            for kv in info.split('&'):
                k_v = kv.split('=')
                if len(k_v) != 2:
                    k = k_v[0]
                    v = ''
                else: k,v = k_v
                if k == 'remarks':
                    self.data['name'] = v
                elif k == 'group':
                    self.data['group'] = v
                elif k == 'obfsparam':
                    self.data['obfs-param'] = v
                elif k == 'protoparam':
                    self.data['protocol-param'] = v

        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname, 
                    'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)}
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k,v = kv.split('=')
                    if k == 'allowInsecure':
                        self.data['skip-cert-verify'] = (v != 0)
                    elif k == 'sni': self.data['sni'] = v
                    elif k == 'alpn':
                        if '%2C' in v:
                            self.data['alpn'] = ["h2", "http/1.1"]
                        else:
                            self.data['alpn'] = [v]
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
        
        else: raise UnsupportedType(self.type)
        self.data['type'] = self.type

    @property
    def url(self):
        data = self.data
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            for key,val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

        if self.type == 'ss':
            passwd = b64encodes_safe(data['cipher']+':'+data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        if self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server','port',
                                        'protocol','cipher','obfs')]) +
                    b64encodes_safe(self.data['password']) +
                    f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
                if k in self.data:
                    ret += '&'+urlk+'='+b64encodes_safe(self.data[k])
            return "ssr://"+ret

        if self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                if len(data['alpn']) >= 2:
                    ret += "alpn=h2%2Chttp%2F1.1&"
                else:
                    ret += f"alpn={quote(data['alpn'][0])}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&')+'#'+name
            return ret

        raise UnsupportedType(self.type)

    @property
    def clash_data(self):
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        return ret

    def supports_clash(self):
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        if self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        if self.data['cipher'] not in supported: return False
        if self.type == 'ssr':
            if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                return False
            if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                return False
        return True

    def supports_ray(self):
        if self.type == 'ss':
            if 'plugin' in self.data and self.data['plugin']: return False
        elif self.type == 'ssr':
            return False
        return True


def get_sub(url):
    global session
    content = ""
    first_line = True
    tp = None
    with session.get(url, stream=True) as r:
        if r.status_code != 200: return r.status_code
        for lineb in r.iter_lines():
            if not lineb: continue
            line = lineb.decode("utf-8").rstrip().replace('\\r','')
            if not line: continue
            if first_line:
                if ': ' in line:
                    tp = 'yaml'
                elif '://' in line:
                    tp = 'sub'#raw
                else: tp = 'sub'
                first_line = False
            if tp == 'yaml':
                if content:
                    if line == "proxy-groups:": break
                    content += line+'\n'
                elif line == "proxies:":
                    content = line+'\n'
            elif tp == 'sub':
                content += line+'\n'
    return content

merged = set()
unknown = set()
names = set()
def merge(text):
    global merged, unknown, names
    if "proxies:" in text:
        # Clash config
        config = yaml.full_load(text.replace("!<str>","!!str"))
        sub = config['proxies']
    else:
        # V2ray Sub
        sub = b64decodes(text.strip()).strip().split('\n')
    if not sub: return
    for p in sub:
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p)
        except: traceback.print_exc()
        else:
            if n not in merged:
                if len(n.data['name']) > 30:
                    n.data['name'] = n.data['name'][:27]+'...'
                while n.data['name'] in names:
                    n.data['name'] += '_'
                names.add(n.data['name'])
                merged.add(n)

def raw2fastly(url):
    url = url[34:].split('/')
    url[1] += '@'+url[2]
    del url[2]
    url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
    return url

if __name__ == '__main__':
    sources = open("sources.list").read().strip().split('\n')
    session = requests.Session()
    if PROXY:
        session.proxies = {'http': PROXY, 'https': PROXY}
    print("正在生成动态链接...")
    set_dynamic_globals(session, LOCAL)
    for auto_fun in AUTOURLS:
        try: url = auto_fun()
        except requests.exceptions.RequestException: pass
        except: traceback.print_exc();raise
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    [sources.append(_) for _ in url]
    print("正在整理链接...")
    sources_final = []
    for source in sources:
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if source[0] == '!':
            if LOCAL: continue
            sub = source[1:]
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            while tags:
                tag = tags.pop(0)
                if tag[0] != '+': break
                if tag == '+date':
                    sub = datetime.datetime.now().strftime(sub)
        if LOCAL and "raw.githubusercontent.com" in sub:
            sub = raw2fastly(sub)
        sources_final.append(sub)
    sources_final.sort()

    print("开始抓取！")
    for source in sources_final:
        print("抓取 '"+source+"'... ", end='', flush=True)
        try:
            res = get_sub(source)
        except KeyboardInterrupt:
            print("正在退出...")
            break
        except requests.exceptions.RequestException:
            print("抓取失败！")
        except: traceback.print_exc()
        else:
            if isinstance(res, int):
                print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(res)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
    print("正在抓取动态节点...")
    for auto_fun in AUTOFETCH:
        try:
            for p in auto_fun():
                try: merged.add(Node(p))
                except KeyboardInterrupt: raise
                except: traceback.print_exc()
        except KeyboardInterrupt: print("正在退出...");break
        except: traceback.print_exc()

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    for p in merged:
        try:
            if p.supports_ray():
                txt += p.url + '\n'
            else: unsupports += 1
        except: traceback.print_exc()
    for p in unknown:
        txt += p+'\n'
    print(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共",
            len(merged)+len(unknown),f"个。{unsupports} 个节点不被 V2Ray 支持。")

    with open("list_raw.txt",'w') as f:
        f.write(txt)
    with open("list.txt",'w') as f:
        f.write(b64encodes(txt))
    print("写出完成！")

    print("正在解析 Adblock 列表...")
    abfbase = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/"
    if LOCAL: abfbase = raw2fastly(abfbase)
    abfurls = (
        "filter_2_Base/filter.txt",
        "filter_224_Chinese/filter.txt",
        "filter_15_DnsFilter/filter.txt"
    )
    blocked = set()
    for url in abfurls:
        try:
            res = session.get(abfbase+url)
        except requests.exceptions.RequestException:
            print(url, "下载失败！")
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().split('\n'):
            line = line.strip()
            if line[:2] == '||' and line[-1] == '^':
                blocked.add(line[2:-1])
    adblock_rules = []
    for domain in blocked:
        adblock_rules.append(f"DOMAIN-SUFFIX,{domain},⛔ 广告拦截")

    print("正在写出 Clash 订阅...")
    with open("config.yml", encoding="utf-8") as f:
        conf = yaml.full_load(f)
    rules = conf['rules']
    rules2 = list(set(rules))
    rules2.sort(key=rules.index)
    conf['rules'] = adblock_rules + rules2
    conf['proxies'] = [_.clash_data for _ in merged if _.supports_clash()]
    with open("list.yml", 'w', encoding="utf-8") as f:
        yaml.dump(conf, f, allow_unicode=True)
    print("写出完成！")
