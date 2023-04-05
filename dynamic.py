#!/usr/bin/env python3
import re
import datetime

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Edg/105.0.1343.53"}

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

def mianfeifq():
    # res_json = session.get('https://api.github.com/repos/mianfeifq/share/contents/').json()
    # for file in res_json:
    #     if file['name'].startswith('data'):
    #         return file['download_url']
    res = session.get("https://raw.githubusercontent.com/mianfeifq/share/main/README.md").text
    return res.split("```")[1].strip().split('\n')

def mux2sub():
    res = session.get("https://raw.githubusercontent.com/RenaLio/Mux2sub/main/sub_list")
    ret = set()
    for line in res.text.strip().split('\n'):
        if line.startswith("http"):
            ret.add(line)

def mux2sub2():
    res = session.get("https://api.github.com/repos/RenaLio/Mux2sub/contents/free?ref=main").json()
    return [_['download_url'] for _ in res]

def sharkdoor():
    res_json = session.get(datetime.datetime.now().strftime(
        'https://api.github.com/repos/sharkDoor/vpn-free-nodes/contents/node-list/%Y-%m?ref=master')).json()
    res = session.get(res_json[-1]['download_url'])
    nodes = set()
    for line in res.text.split('\n'):
        if '://' in line:
            nodes.add(line.split('|')[-2])
    return nodes

AUTOURLS = (kkzui, mux2sub, mux2sub2)
AUTOFETCH = (sharkdoor, mianfeifq)

if __name__ == '__main__':
    import requests
    set_dynamic_globals(requests.Session(), True)
