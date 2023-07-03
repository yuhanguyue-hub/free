#!/usr/bin/env python3
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
import datetime
import traceback
import binascii
import threading
import sys
import os
from types import FunctionType as function
from typing import Set, List, Dict, Union, Any

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

DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id', 
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_EXAMPLE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

ABFURLS = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt"
)

FAKE_IPS = "8.8.8.8; 8.8.4.4; 1.1.1.1; 1.0.0.1; 4.2.2.2; 4.2.2.1; 114.114.114.114".split('; ')
FAKE_DOMAINS = ".google.com .github.com .sb".split()

FETCH_TIMEOUT = (6, 5)

# !!! JUST FOR DEBUGING !!!
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

session = requests.Session()
exc_queue: List[str] = []

class Node:
    names: Set[str] = set()

    def __init__(self, data) -> None:
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
        self.data['type'] = self.type
        self.name = self.data['name']

    def __str__(self):
        return self.url

    def __hash__(self):
        try:
            return hash(f"{self.type}:{self.data['server']}:{self.data['port']}")
        except Exception: return hash('__ERROR__')
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    def load_url(self, url: str) -> None:
        try: self.type, dt = url.split("://")
        except ValueError: raise NotANode(url)
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        # === Fix end ===
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            try: v.update(json.loads(b64decodes(dt)))
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
            elif v['net'] == 'h2':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['host'] = v.split(',')
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}

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
                parts = dt.split(':')
            else:
                parts = b64decodes_safe(dt).split(':')
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

    def format_name(self, max_len=30) -> None:
        self.data['name'] = self.name
        if len(self.data['name']) > max_len:
            self.data['name'] = self.data['name'][:max_len]+'...'
        if self.data['name'] in Node.names:
            i = 0
            new: str = self.data['name']
            while new in Node.names:
                i += 1
                new = f"{self.data['name']} #{i}"
            self.data['name'] = new
        
    @property
    def isfake(self) -> bool:
        if 'server' not in self.data: return True
        if '.' not in self.data['server']: return True
        if self.data['server'] in FAKE_IPS: return True
        for domain in FAKE_DOMAINS:
            if self.data['server'] == domain.lstrip('.'): return True
            if self.data['server'].endswith(domain): return True
        # TODO: Fake UUID
        if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            return True
        return False

    @property
    def url(self) -> str:
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
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
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
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret: del ret['group']
        return ret

    def supports_clash(self) -> bool:
        if self.isfake: return False
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            # A quick fix for #2
            self.data['tls'] = True
        if self.type == 'vless': return False
        if self.data['type'] == 'vless': return False
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        elif self.type == 'vmess':
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
        if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                and not self.data['plugin-opts']['mode']: return False
        return True

    def supports_ray(self) -> bool:
        if self.isfake: return False
        # if self.type == 'ss':
        #     if 'plugin' in self.data and self.data['plugin']: return False
        # elif self.type == 'ssr':
        #     return False
        return True

class Source():
    def __init__(self, url: Union[str, function]) -> None:
        if isinstance(url, function):
            self.url: str = "dynamic://"+url.__name__
            self.url_source: function = url
        elif url.startswith('+'):
            self.url_source: str = url
            self.date = datetime.datetime.now()# + datetime.timedelta(days=1)
            self.gen_url()
        else:
            self.url: str = url
            self.url_source: None = None
        self.content: Union[str, List[str], int] = None
        self.sub: list = None

    def gen_url(self) -> None:
        self.url_source: str
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    def get(self, depth=2) -> None:
        global exc_queue
        if self.content: return
        try:
            if self.url.startswith("dynamic:"):
                content: Union[str, List[str]] = self.url_source()
            else:
                global session
                content: str = ""
                with session.get(self.url, stream=True) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t"+self.url
                            exc_queue.append(exc)
                            self.get(depth-1)
                        else:
                            self.content = r.status_code
                        return
                    # for lineb in r.iter_lines():
                    tp = None
                    pending = None
                    for chunk in r.iter_content(decode_unicode=True):
                        chunk: str
                        if pending is not None:
                            chunk = pending + chunk
                            pending = None
                        if tp == 'sub':
                            content += chunk
                            continue
                        lines: List[str] = chunk.splitlines()
                        if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                            pending = lines.pop()
                        while lines:
                            line = lines.pop(0).rstrip().replace('\\r','')
                            if not line: continue
                            if not tp:
                                if ': ' in line:
                                    kv = line.split(': ')
                                    if len(kv) == 2 and kv[0].isalpha():
                                        tp = 'yaml'
                                elif line[0] == '#': pass
                                else: tp = 'sub'
                            if tp == 'yaml':
                                if content:
                                    if line == "proxy-groups:": break
                                    content += line+'\n'
                                elif line == "proxies:":
                                    content = line+'\n'
                            elif tp == 'sub':
                                content = chunk
                    if pending is not None: content += pending
        except KeyboardInterrupt: raise
        except requests.exceptions.RequestException:
            self.content = -1
        except:
            self.content = -2
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            exc_queue.append(exc)
        else:
            self.content: Union[str, List[str]] = content
            self.parse()

    def parse(self) -> None:
        global exc_queue
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    # Clash config
                    config = yaml.full_load(text.replace("!<str>","!!str"))
                    sub: List[str] = config['proxies']
                elif '://' in text:
                    # V2Ray raw list
                    sub = text.strip().splitlines()
                else:
                    # V2Ray Sub
                    sub = b64decodes(text.strip()).strip().splitlines()
            else: sub = text # 动态节点抓取后直接传入列表
            self.sub = sub
        except KeyboardInterrupt: raise
        except: exc_queue.append(
                "在解析 '"+self.url+"' 时发生错误：\n"+traceback.format_exc())

def extract(url: str) -> Set[str]:
    global session
    res = session.get(url)
    if res.status_code != 200: return res.status_code
    urls = set()
    for line in res.text:
        if line.startswith("http"):
            urls.add(line)
    return urls

merged: Set[Node] = set()
unknown: Set[str] = set()
used: Dict[int, List[int]] = {}
def merge(source_obj: Source, sourceId=-1) -> None:
    global merged, unknown
    sub = source_obj.sub
    if not sub: print("空订阅，跳过！", end='', flush=True); return
    for p in sub:
        if isinstance(p, str):
            if not p.isascii() or '://' not in p: continue
            ok = True
            for ch in '!|@#`~()[]{} ':
                if ch in p:
                    ok = False; break
            if not ok: continue
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p)
        except: traceback.print_exc()
        else:
            if n not in merged:
                n.format_name()
                Node.names.add(n.data['name'])
                merged.add(n)
            if hash(n) not in used:
                used[hash(n)] = []
            used[hash(n)].append(sourceId)

def raw2fastly(url: str) -> str:
    # 由于 Fastly CDN 不好用，因此换成 ghproxy.net，见 README。
    # 2023/06/27: ghproxy.com 比 ghproxy.net 稳定性更好，为避免日后代码失效，进行修改
    # 2023/06/28: ghproxy.com 似乎有速率或并发限制，改回原来的镜像
    # url = url[34:].split('/')
    # url[1] += '@'+url[2]
    # del url[2]
    # url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
    # return url
    if not LOCAL: return url
    if url.startswith("https://raw.githubusercontent.com/"):
        return "https://ghproxy.net/"+url
    return url

def main():
    global exc_queue, FETCH_TIMEOUT, ABFURLS
    from dynamic import AUTOURLS, AUTOFETCH, set_dynamic_globals
    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if DEBUG_NO_NODES:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        AUTOURLS = AUTOFETCH = sources = []
    if PROXY: session.proxies = {'http': PROXY, 'https': PROXY}
    session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'
    print("正在生成动态链接...")
    set_dynamic_globals(session, LOCAL)
    for auto_fun in AUTOURLS:
        print("正在生成 '"+auto_fun.__name__+"'... ", end='', flush=True)
        try: url = auto_fun()
        except requests.exceptions.RequestException: print("失败！")
        except: print("错误：");traceback.print_exc()
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                print("成功！")
            else: print("跳过！")
    print("正在整理链接...")
    sources_final = set()
    airports = set()
    for source in sources:
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    if airports:
        print("正在抓取机场列表...")
        for sub in airports:
            print("合并 '"+sub+"'... ", end='', flush=True)
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                print("正在退出...")
                break
            except requests.exceptions.RequestException:
                print("合并失败！")
            except: traceback.print_exc()
            else:
                if isinstance(res, int):
                    print(res)
                else:
                    for url in res:
                        sources_final.add(url)
                    print("完成！")

    print("正在整理链接...")
    sources_final = list(sources_final)
    sources_final.sort()
    sources_obj = [Source(url) for url in (sources_final + AUTOFETCH)]

    print("开始抓取！")
    threads = [threading.Thread(target=_.get, daemon=True) for _ in sources_obj]
    for thread in threads: thread.start()
    for i in range(len(sources_obj)):
        try:
            for t in range(1, FETCH_TIMEOUT[0]+1):
                print("抓取 '"+sources_obj[i].url+"'... ", end='', flush=True)
                try: threads[i].join(timeout=FETCH_TIMEOUT[1])
                except KeyboardInterrupt:
                    print("正在退出...")
                    FETCH_TIMEOUT = (1, 0)
                    break
                if not threads[i].is_alive(): break
                print(f"{5*t}s")
            if threads[i].is_alive():
                print("超时！")
                continue
            res = sources_obj[i].content
            if isinstance(res, int):
                if res < 0: print("抓取失败！")
                else: print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(sources_obj[i], sourceId=i)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
        except KeyboardInterrupt:
            print("正在退出...")
            break
        while exc_queue:
            print(exc_queue.pop(0), file=sys.stderr, flush=True)

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    for p in merged:
        try:
            if hash(p) in used:
                # 注意：这一步也会影响到下方的 Clash 订阅，不用再执行一遍！
                p.data['name'] = ','.join([str(_) for _ in sorted(used[hash(p)])])+'|'+p.data['name']
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

    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)
    if DEBUG_NO_ADBLOCK:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
        ABFURLS = ()
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(url)
        except requests.exceptions.RequestException:
            print(url, "下载失败！")
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                            (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))
    adblock_rules: List[str] = []
    for domain in blocked:
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.','').isdigit(): # IP
            for seg in segs: # '223.73.212.020' is not valid
                if not seg: break
                if seg[0] == '0' and seg != '0': break
            else:
                adblock_rules.append(f"IP-CIDR,{domain}/32,{conf['proxy-groups'][-1]['name']}")
        else:
            adblock_rules.append(f"DOMAIN-SUFFIX,{domain},{conf['proxy-groups'][-1]['name']}")
    print(f"共有 {len(adblock_rules)} 条规则")

    print("正在写出 Clash 订阅...")
    rules2: Dict[str, str] = {}
    match_rule = None
    for rule in conf['rules']:
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ','+rresolve
        else: print("规则 '"+rule+"' 无法被解析！")
        k = rtype+','+rargument
        if k not in rules2:
            rules2[k] = rpolicy
    rules = [','.join(_) for _ in rules2.items()]+[match_rule]
    conf['rules'] = adblock_rules + rules
    conf['proxies'] = []
    names_clash: Set[str] = set()
    for p in merged:
        if p.supports_clash():
            conf['proxies'].append(p.clash_data)
            names_clash.add(p.data['name'])
    names_clash = list(names_clash)
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))

    print("正在写出配置片段...")
    with open("snippets/nodes.yml", 'w', encoding="utf-8") as f:
        yaml.dump({'proxies': conf['proxies']}, f, allow_unicode=True)
    try:
        with open("snippets/_config.yml", encoding="utf-8") as f:
            snip_conf: Dict[Any] = yaml.full_load(f)
    except (OSError, yaml.error.YAMLError):
        print("配置文件读取失败：")
        traceback.print_exc()
    else:
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values(): snippets[rpolicy] = []
        for rule, rpolicy in rules2.items():
            if ',' in rpolicy: rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        snippets['ADBLOCK'] = [','.join(_.split(',')[:-1]) for _ in adblock_rules]
        for name, payload in snippets.items():
            with open("snippets/"+name+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: out += f"{len(source.sub)}"
        except: out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    open("list_result.csv",'w').write(out)

    print("写出完成！")

if __name__ == '__main__':
    main()
