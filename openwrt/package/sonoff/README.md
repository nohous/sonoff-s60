# sonoff - OpenWRT package for Sonoff S60TPF

Control Sonoff S60TPF smart plugs via local HTTP API. No cloud, no Home Assistant, just ~17KB of code.

## What's included

| File | Size | Purpose |
|------|------|---------|
| `aes_cbc.so` | ~10KB | ucode module wrapping mbedtls (AES-128-CBC, MD5, base64) |
| `sonoff` | ~5KB | ucode CLI script |
| `lamp.html` | ~2KB | Web UI with big ON/OFF buttons |
| `cgi-bin/sonoff` | 356B | CGI glue |

## Dependencies

- `libucode` - ucode interpreter (already on OpenWRT with LuCI)
- `libmbedtls` - crypto library (already on OpenWRT)
- `curl` - HTTP client (~200KB, pulls in libcurl)

## Building

### 1. Get the SDK

Download the SDK matching your router's target:

```bash
# Example for ramips/mt7621 (check your router's target!)
wget https://downloads.openwrt.org/releases/24.10.0/targets/ramips/mt7621/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64.tar.zst
tar --zstd -xf openwrt-sdk-*.tar.zst
```

Find your target with: `ssh router "cat /etc/openwrt_release | grep TARGET"`

### 2. Link the package

```bash
ln -s $(pwd)/package/sonoff openwrt-sdk-*/package/
```

### 3. Update feeds (first time only)

```bash
cd openwrt-sdk-*
./scripts/feeds update -a
./scripts/feeds install libucode libmbedtls curl
```

### 4. Build

```bash
make package/sonoff/compile V=s
```

Output: `bin/packages/mipsel_24kc/base/sonoff_1.0-2_mipsel_24kc.ipk`

## Installing

```bash
# Copy to router
scp bin/packages/*/base/sonoff*.ipk router:/tmp/

# Install
ssh router "opkg install /tmp/sonoff*.ipk"
```

Or if no SCP:
```bash
cat bin/packages/*/base/sonoff*.ipk | ssh router "cat > /tmp/sonoff.ipk && opkg install /tmp/sonoff.ipk"
```

## Configuration

Edit device credentials in `/usr/bin/sonoff` on the router:

```javascript
const DEVICE_IP = '192.168.1.28';
const DEVICE_ID = '10026ede0c';
const DEVICE_KEY = '3cc3bdc8-20fd-44be-b348-44b8bba4bdbb';
const API_KEY = '265da2d7-bb39-42c4-9047-9960178f706b';
```

Get these from Bluetooth pairing or sniffing the eWeLink app.

## Usage

### CLI

```bash
sonoff on      # turn on
sonoff off     # turn off
sonoff energy  # show last 24h power consumption
```

### Web UI

Open `http://<router-ip>/lamp.html` in browser.

## Protocol notes

The Sonoff S60TPF uses:
- HTTP POST to port 8081
- AES-128-CBC encryption with PKCS7 padding
- Key = MD5(device_key)
- IV = random 16 bytes per request
- Payload must include: `sequence`, `deviceid`, `selfApikey`, `encrypt`, `iv`, `data`

Device **ignores/hangs** on invalid payloads - it only responds to properly encrypted requests.

## License

WTFPL
