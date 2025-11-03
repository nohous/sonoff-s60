#!/usr/bin/env python3
"""Sonoff S60TPF control - HTTP version"""

import requests
import json
import base64
import time
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt(data, devicekey):
    iv = get_random_bytes(16)
    key = MD5.new(devicekey.encode()).digest()
    plaintext = json.dumps(data).encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return {
        'iv': base64.b64encode(iv).decode(),
        'data': base64.b64encode(ciphertext).decode()
    }

def decrypt(msg, devicekey):
    key = MD5.new(devicekey.encode()).digest()
    iv = base64.b64decode(msg['iv'])
    ciphertext = base64.b64decode(msg['data'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return json.loads(plaintext)

def send_command(ip, deviceid, devicekey, params):
    """Send command via HTTP POST"""
    url = f'http://{ip}:8081/zeroconf/switches'
    
    encrypted = encrypt(params, devicekey)
    decrypted = decrypt(encrypted, devicekey)
    
    print(f"We send: {decrypted}")
    
    payload = {
        'sequence': str(int(time.time() * 1000)),
        'deviceid': deviceid,
        'selfApikey': '123',
        'encrypt': True,
        **encrypted
    }
    
    headers = {
        'User-Agent': 'PenisLAN/3.9.3',
        'Content-Type': 'application/json',
        'Connection': 'close',
        'Accept': '*/*'
    }
    
    print(f"POST {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    response = requests.post(url, json=payload, headers=headers, timeout=5)
    
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Response: {result}")
    
    if result.get('error') != 0:
        raise Exception(f"Command failed: {result}")
    
    return result

if __name__ == '__main__':
    DEVICE_IP = '192.168.1.28'
    DEVICE_ID = '10026ede0c'
    DEVICE_KEY = '3cc3bdc8-20fd-44be-b348-44b8bba4bdbb'
    ha_data = "DtFQNDJjOCJndMePK4Z0MrxVBVqfiOe96tvPcJ/dEdkdBe+KJJb3SSYWvqzu2khFiMeSTIPueV9JFjBG7crpZQ=="
    ha_iv = "841Nyp+QEvcEXNykT0lopg=="

    decrypted = decrypt({'data': ha_data, 'iv': ha_iv}, DEVICE_KEY)
    print(f"HA sends: {decrypted}")
    
    import sys
    command = sys.argv[1] if len(sys.argv) > 1 else 'on'
    
    # Build the switches array like HA does
    params = {
        'switches': [
            {
                'outlet': 0,
                'switch': command
            }
        ],
        'operSide': 1
    }
    
    print(f"Sending '{command}' to S60TPF at {DEVICE_IP}...")
    try:
        result = send_command(DEVICE_IP, DEVICE_ID, DEVICE_KEY, params)
        print(f"\nSUCCESS!")
    except Exception as e:
        print(f"\nERROR: {e}")