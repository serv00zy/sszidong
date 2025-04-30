import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime

print(f"Date   : {datetime.today().strftime('%Y-%m-%d')}")

a = 'http://api.skrapp.net/api/serverlist'
b = {
    'accept': '/',
    'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
    'appversion': '1.3.1',
    'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
    'content-type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=9frhbj5smojt2o0k1djbeluf92'
}
c = {'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'}
d = b'65151f8d966bf596'
e = b'88ca0f0ea1ecf975'

def f(g, d, e):
    h = pyaes.AESModeOfOperationCBC(d, iv=e)
    i = b''.join(h.decrypt(g[j:j+16]) for j in range(0, len(g), 16))
    return i[:-i[-1]]

try:
    j = requests.post(a, headers=b, data=c)
    if j.status_code == 200:
        k = j.text.strip()
        l = binascii.unhexlify(k)
        m = f(l, d, e)
        n = json.loads(m)
        
        # 生成所有的ss://链接
        ss_links = []
        for o in n['data']:
            p = f"aes-256-cfb:{o['password']}@{o['ip']}:{o['port']}"
            q = base64.b64encode(p.encode('utf-8')).decode('utf-8')
            r = f"ss://{q}#{o['title']}"
            ss_links.append(r)
        
        # 将所有链接转换为base64编码
        all_links_base64 = base64.b64encode('\n'.join(ss_links).encode('utf-8')).decode('utf-8')
        
        # 将base64编码的内容写入ss.txt文件
        with open('ss.txt', 'w', encoding='utf-8') as file:
            file.write(all_links_base64)
            print(all_links_base64)
    else:
        print(f"Failed to retrieve data, status code: {j.status_code}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
    print("Please check the URL and your network connection, and try again.")
