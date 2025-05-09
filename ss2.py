import requests
import base64
import json
import pyaes
import binascii
from datetime import datetime

# 打印当前日期
print(f"Date   : {datetime.today().strftime('%Y-%m-%d')}")

# API 地址和请求参数
url = 'http://api.skrapp.net/api/serverlist'
headers = {
    'accept': '/',
    'accept-language': 'zh-Hans-CN;q=1, en-CN;q=0.9',
    'appversion': '1.3.1',
    'user-agent': 'SkrKK/1.3.1 (iPhone; iOS 13.5; Scale/2.00)',
    'content-type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=9frhbj5smojt2o0k1djbeluf92'
}
post_data = {
    'data': '4265a9c353cd8624fd2bc7b5d75d2f18b1b5e66ccd37e2dfa628bcb8f73db2f14ba98bc6a1d8d0d1c7ff1ef0823b11264d0addaba2bd6a30bdefe06f4ba994ed'
}
key = b'65151f8d966bf596'  # AES 密钥
iv = b'88ca0f0ea1ecf975'  # AES IV

# 解密函数
def decrypt_data(cipher_bytes, key, iv):
    try:
        aes = pyaes.AESModeOfOperationCBC(key, iv=iv)
        decrypted = b''.join([aes.decrypt(cipher_bytes[i:i+16]) for i in range(0, len(cipher_bytes), 16)])
        pad = decrypted[-1]
        if pad < 1 or pad > 16:
            raise ValueError("Invalid PKCS#7 padding")
        return decrypted[:-pad]
    except Exception as err:
        print(f"[Decryption Error] {err}")
        return None

try:
    # 发送请求
    response = requests.post(url, headers=headers, data=post_data)
    print(f"[HTTP Status] {response.status_code}")

    # 如果请求成功，处理数据
    if response.status_code == 200:
        raw_hex = response.text.strip()
        print(f"[Raw HEX] {raw_hex[:60]}...")  # 截断显示前60字符

        # 如果 HEX 长度不是偶数，进行调整
        if len(raw_hex) % 2 != 0:
            raw_hex = raw_hex[:len(raw_hex)//2 * 2]

        try:
            cipher_bytes = binascii.unhexlify(raw_hex)
        except binascii.Error as hex_err:
            print(f"[HEX Decode Error] {hex_err}")
            exit(1)

        decrypted_bytes = decrypt_data(cipher_bytes, key, iv)
        if not decrypted_bytes:
            print("[Error] Failed to decrypt. Check key/IV.")
            exit(1)

        try:
            server_data = json.loads(decrypted_bytes)
        except json.JSONDecodeError as json_err:
            print(f"[JSON Error] {json_err}")
            print(f"Decrypted content: {decrypted_bytes}")
            exit(1)

        # 检查 JSON 中是否包含 'data' 字段
        if 'data' not in server_data:
            print("[Error] 'data' field missing in response JSON.")
            print(server_data)
            exit(1)

        # 生成 ss:// 链接
        ss_links = []
        for item in server_data['data']:
            ss_info = f"aes-256-cfb:{item['password']}@{item['ip']}:{item['port']}"
            encoded = base64.b64encode(ss_info.encode()).decode()
            ss_link = f"ss://{encoded}#{item['title']}"
            ss_links.append(ss_link)

        # 将所有 SS 链接转为 Base64 编码
        final_base64 = base64.b64encode('\n'.join(ss_links).encode()).decode()

        # 将最终 Base64 编码后的链接写入文件
        with open('ss.txt', 'w', encoding='utf-8') as f:
            f.write(final_base64)
        print("[Success] SS links written to ss.txt")

    else:
        print(f"[API Error] Status: {response.status_code}")
        print(f"Response: {response.text}")

except requests.exceptions.RequestException as req_err:
    print(f"[Request Error] {req_err}")
