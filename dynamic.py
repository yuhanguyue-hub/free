#!/usr/bin/env python3
import re
import datetime
import requests

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"}
session: requests.Session
LOCAL: bool

def set_dynamic_globals(_session, _LOCAL):
    global session, LOCAL
    session = _session
    LOCAL = _LOCAL


def kkzui():
    res = session.get("https://kkzui.com/jd?orderby=modified",headers=headers)
    article_url = re.search(r'<h2 class="item-heading"><a href="(https://kkzui.com/(.*?)\.html)">20(.*?)号(.*?)个高速免费节点(.*?)免费代理</a></h2>',res.text).groups()[0]
    res = session.get(article_url,headers=headers)
    sub_url = re.search(r'<p><strong>这是v2订阅地址</strong>：(.*?)</p>',res.text).groups()[0]
    return sub_url

def sharkdoor():
    res_json = session.get(datetime.datetime.now().strftime(
        'https://api.github.com/repos/sharkDoor/vpn-free-nodes/contents/node-list/%Y-%m?ref=master')).json()
    res = session.get(res_json[-1]['download_url'])
    nodes = set()
    for line in res.text.split('\n'):
        if '://' in line:
            nodes.add(line.split('|')[-2])
    return nodes

def changfengoss():
    res = session.get(datetime.datetime.now().strftime(
        "https://api.github.com/repos/changfengoss/pub/contents/data/%Y_%m_%d?ref=main")).json()
    return [_['download_url'] for _ in res]

def vpn_fail():
    # From https://github.com/mahdibland/get_v2/blob/main/get_clash.py
    response = session.get("https://vpn.fail/free-proxy/type/v2ray").text
    ips = re.findall(r'<a href=\"https://vpn\.fail/free-proxy/ip/(.*?)\" style=', response)
    links = set()
    for ip in ips:
        try:
            response = session.get(f"https://vpn.fail/free-proxy/ip/{ip}").text
            link = response.split('class="form-control text-center" id="pp2" value="')[1].split('"')[0]
            links.add(link)
        except requests.exceptions.RequestException: pass
    return links

def w1770946466():
    res = session.get("https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/README.md").text
    subs = set()
    for line in res.strip().split('\n'):
        if line.startswith("`http"):
            sub = line.split('`')[1]
            if not sub.startswith("https://raw.githubusercontent.com"):
                subs.add(sub)
    return sub


AUTOURLS = (kkzui, changfengoss, w1770946466)
AUTOFETCH = (sharkdoor, vpn_fail)

if __name__ == '__main__':
    import requests
    set_dynamic_globals(requests.Session(), True)
