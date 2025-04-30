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

def decrypt_data(g, d, e):
    try:
        h = pyaes.AESModeOfOperationCBC(d, iv=e)
        decrypted = b''.join([h.decrypt(g[i:i+16]) for i in range(0, len(g), 16)])
        # 处理PKCS#7填充
        pad = decrypted[-1]
        if pad < 1 or pad > 16:
            raise ValueError("Invalid padding")
        decrypted = decrypted[:-pad]
        return decrypted
    except Exception as dec_err:
        print(f"Decryption error: {dec_err}")
        return None

try:
    j = requests.post(a, headers=b, data=c)
    print(f"HTTP Status Code: {j.status_code}")
    
    if j.status_code == 200:
        k = j.text.strip()
        print(f"Raw response (hex): {k}")
        
        # 检查是否为有效的hex字符串
        if len(k) % 2 != 0:
            k = k[:len(k)//2 * 2]  # 调整长度为偶数
            
        try:
            l = binascii.unhexlify(k)
        except binascii.Error as err:
            print(f"Hex decode error: {err}")
            exit(1)
            
        m = decrypt_data(l, d, e)
        if m is None:
            print("Decryption failed. Check keys/IV.")
            exit(1)
            
        print(f"Decrypted data: {m}")
        
        try:
            n = json.loads(m)
        except json.JSONDecodeError as json_err:
            print(f"JSON parse error: {json_err}")
            exit(1)
            
        # 检查是否存在'data'字段
        if 'data' not in n:
            print("Error: 'data' field missing in JSON response.")
            print("Full JSON content:", n)
            exit(1)
            
        # 生成ss://链接
        ss_links = []
        for o in n['data']:
            config = f"aes-256-cfb:{o['password']}@{o['ip']}:{o['port']}"
            encoded = base64.b64encode(config.encode()).decode()
            ss_link = f"ss://{encoded}#{o['title']}"
            ss_links.append(ss_link)
        
        # 编码并写入文件
        all_links = '\n'.join(ss_links)
        base64_links = base64.b64encode(all_links.encode()).decode()
        with open('ss.txt', 'w', encoding='utf-8') as f:
            f.write(base64_links)
        print("Successfully wrote to ss.txt")
        
    else:
        print(f"API Error: {j.status_code}")
        print("Response:", j.text)
        
except requests.exceptions.RequestException as req_err:
    print(f"Request failed: {req_err}")
