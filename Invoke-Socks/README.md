# SOCKS5 Proxy in PowerShell

## Overview

This project provides a lightweight SOCKS5 proxy server implemented in PowerShell. The proxy enables forwarding traffic from clients to destination servers via the SOCKS5 protocol, making it useful for penetration testing, red teaming, or network pivoting scenarios.

---

## Features

- SOCKS5 protocol support.
- No authentication required (by default).
- Relays TCP traffic between clients and destination servers.
- Lightweight and portable, running entirely in PowerShell.
- Customisable IP address and port configuration.

---

## Requirements

- **PowerShell Version**: Requires PowerShell 5.1 or later.
  - Requires [https://www.powershellgallery.com/packages/ThreadJob/2.0.3](ThreadJob) module for PowerShell 5.1.
- **Permissions**: Administrator privileges to bind to ports below 1024 (if needed).

---

## Installation

1. Download the `Invoke-Socks` script and save it as `Invoke-Socks.psm1`.
2. Open a PowerShell terminal.
3. Import the script using:
   ```powershell
   . .\Invoke-Socks.psm1
  ```

## Usage

### Start the SOCKS5 Proxy

To start the proxy, use the `Invoke-Socks` command with the desired port and (optionally) IP address:

```powershell
Invoke-Socks -Port 8888
```

By default, the proxy listens on all network interfaces (`0.0.0.0`).

### Example with Specific IP

To bind to a specific IP address:

```powershell
Invoke-Socks -Port 8888 -Ip "127.0.0.1"
```

### Test the Proxy

Use `curl` or any application supporting SOCKS5 proxies:

```bash
curl --proxy socks5h://127.0.0.1:8888 http://example.com
```

## Limitations

- **No Authentication**: The proxy currently does not support SOCKS5 authentication.
- **TCP Only**: The proxy supports TCP traffic only. UDP forwarding is not implemented.
- **Single Thread per Connection**: Each client connection is handled in a separate thread, which may limit performance under heavy load.
