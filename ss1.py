import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime

print(f"Date   : {datetime.today().strftime('%Y-%m-%d')}")

url = 'http://api.skrapp.net/api/serverlist'
headers = {
    'accept': '/',
    'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
    'appversion': '1.3.1',
    'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
    'content-type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=9frhbj5smojt2o0k1djbeluf92',  # 替换为最新 Cookie
}
data = {'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'}
key = b'65151f8d966bf596'
iv = b'88ca0f0ea1ecf975'

def decrypt_aes(ciphertext, key, iv):
    aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
    plaintext = b''.join(aes.decrypt(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16))
    return plaintext.rstrip(b'\x00')  # 去除填充字符

try:
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        hex_data = response.text.strip()
        encrypted_bytes = binascii.unhexlify(hex_data)
        decrypted_bytes = decrypt_aes(encrypted_bytes, key, iv)
        
        # 打印原始数据供调试
        print("Decrypted raw data:")
        print(decrypted_bytes.decode('utf-8'))
        
        try:
            parsed_data = json.loads(decrypted_bytes)
            
            # 根据实际字段名修改（例如 servers 替代 data）
            for server in parsed_data.get('servers', []):  # 使用 .get() 避免 KeyError
                ss_url = f"ss://{base64.b64encode(f'aes-256-cfb:{server[\"password\"]}@{server[\"ip\"]}:{server[\"port\"]}').decode()}#{server.get('title', '')}"
                print(ss_url)
                
            # 写入文件
            with open('ss.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join([
                    f"ss://{base64.b64encode(f'aes-256-cfb:{s["password"]}@{s["ip"]}:{s["port"]}').decode()}#{s.get('title', '')}" 
                    for s in parsed_data.get('servers', [])
                ]))
        except json.JSONDecodeError as je:
            print(f"JSON 解析失败: {je}")
            print("原始数据:", decrypted_bytes)
    else:
        print(f"请求失败，状态码: {response.status_code}")
except Exception as e:
    print(f"发生异常: {e}")
