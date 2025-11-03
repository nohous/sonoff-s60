import requests
import json
import base64
import time
import sys
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

#def get_info(ip, deviceid, devicekey, apikey):
#    url = f'http://{ip}:8081/zeroconf/info'
#    
#    payload = {
#        'sequence': str(int(time.time() * 1000)),
#        'deviceid': deviceid,
#        'selfApikey': apikey,
#        'data': {}  # Empty data for query
#    }
#    
#    headers = {
#        'User-Agent': 'PenisLAN/3.9.3',
#        'Content-Type': 'application/json',
#    }
#    
#    response = requests.post(url, json=payload, headers=headers, timeout=5)
#    result = response.json()
#    
#    if result.get('error') != 0:
#        raise Exception(f"Query failed with error {result.get('error')}")
#    
#    # Response contains: switch, current, power, voltage, etc.
#    return result.get('data', result)

def get_energy(ip, deviceid, devicekey, apikey, start=0, end=743):
    """Get hourly energy consumption data
    
    Args:
        start: Start hour index (0-743 for 31 days)
        end: End hour index
    """
    url = f'http://{ip}:8081/zeroconf/getHoursKwh'
    
    encrypted = encrypt({'getHoursKwh': {'start': start, 'end': end}}, devicekey)
    
    payload = {
        'sequence': str(int(time.time() * 1000)),
        'deviceid': deviceid,
        'selfApikey': apikey,
        'encrypt': True,
        **encrypted
    }
    
    headers = {
        'User-Agent': 'PenisLAN/3.9.3',
        'Content-Type': 'application/json',
    }
    
    response = requests.post(url, json=payload, headers=headers, timeout=5)
    result = response.json()
    
    if result.get('error') != 0:
        raise Exception(f"Energy query failed with error {result.get('error')}")
    
    # Decrypt response
    if result.get('encrypt'):
        decrypted = decrypt(result, devicekey)
        return decrypted
    
    return result

def send_command(ip, deviceid, devicekey, apikey, params):
    url = f'http://{ip}:8081/zeroconf/switches'
    
    encrypted = encrypt(params, devicekey)
    
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
    
    response = requests.post(url, json=payload, headers=headers, timeout=5)
    
    result = response.json()
    
    if result.get('error') != 0:
        raise Exception(f"Command failed: {result}")
    
    return result

if __name__ == '__main__':
    DEVICE_IP = '192.168.1.28'
    DEVICE_ID = '10026ede0c'
    DEVICE_KEY = '3cc3bdc8-20fd-44be-b348-44b8bba4bdbb'
    API_KEY = '265da2d7-bb39-42c4-9047-9960178f706b'
    
    # Commands: on, off
    if len(sys.argv) < 2:
        print("Usage: python sonoff.py <command>")
        print("Commands: on, off, status, energy")
        sys.exit(1)
    
    command = sys.argv[1]

    try:
        #if command == 'status':
        #    # Get current state
        #    print("Querying device status...")
        #    info = get_info(DEVICE_IP, DEVICE_ID, DEVICE_KEY, API_KEY)
        #    print(json.dumps(info, indent=2))
        #    
        #    # Parse the useful bits
        #    data = info.get('data', info)
        #    print(f"\nSwitch: {data.get('switch', 'unknown')}")
        #    print(f"Power: {data.get('power', 0)} W")
        #    print(f"Voltage: {data.get('voltage', 0) / 100} V")
        #    print(f"Current: {data.get('current', 0) / 100} A")
            
        if command == 'energy':
            # Get last 24 hours of energy data
            print("Querying energy data (last 24 hours)...")
            energy = get_energy(DEVICE_IP, DEVICE_ID, DEVICE_KEY, API_KEY, start=0, end=23)
            print(json.dumps(energy, indent=2))
            
            # Decode the hex string if present
            if 'hoursKwhData' in energy:
                raw = energy['hoursKwhData']
                # Format: 3 chars per hour - 1 hex + 2 decimal digits
                hours = []
                for i in range(0, len(raw), 3):
                    kwh = int(raw[i], 16) + int(raw[i+1:i+3], 10) * 0.01
                    hours.append(round(kwh, 2))
                
                print(f"\nEnergy per hour (last {len(hours)} hours):")
                for i, kwh in enumerate(hours):
                    print(f"  Hour {i}: {kwh} kWh")
                print(f"\nTotal: {sum(hours):.2f} kWh")
            
        else:
            # on/off command
            params = {
                'switches': [{'outlet': 0, 'switch': command}],
                'operSide': 1
            }
            
            result = send_command(DEVICE_IP, DEVICE_ID, DEVICE_KEY, API_KEY, params)
            print(f"SUCCESS")

    except Exception as e:
        print(f"ERROR: {e}")

# Reference data from wireshark with Homeassistant + sonoffLAN
#    ha_data = "DtFQNDJjOCJndMePK4Z0MrxVBVqfiOe96tvPcJ/dEdkdBe+KJJb3SSYWvqzu2khFiMeSTIPueV9JFjBG7crpZQ=="
#    ha_iv = "841Nyp+QEvcEXNykT0lopg=="
#
#    decrypted = decrypt({'data': ha_data, 'iv': ha_iv}, DEVICE_KEY)
#    print(f"HA sends: {decrypted}")
    
