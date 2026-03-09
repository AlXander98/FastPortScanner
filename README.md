<h1 align="center">FastPortScanner</h1>

<h3 align="center">A high-performance TCP port scanner written in Java using non-blocking I/O (java.nio).</h3>

Designed to scan thousands of ports quickly while collecting **basic service banners and fingerprints**.

The scanner uses a **pipeline architecture with asynchronous sockets and selectors**, allowing a large number of concurrent connections while keeping resource usage relatively low.

---

## Features

* ⚡ **Fast asynchronous scanning** using Java NIO
* 🔗 **Up to 2000 concurrent connections**
* 📡 **Banner grabbing** for service identification
* 🧠 **Basic service fingerprinting**
* 🎯 **Top-25 ports quick scan mode**
* 📊 **Live progress bar**
* 🎨 **Colored terminal output**
* 📋 **Automatic service detection**

---

## How It Works

Instead of scanning ports sequentially, the scanner uses a **non-blocking pipeline model**:

1. Ports are queued for scanning.
2. Multiple connections are opened asynchronously.
3. When a connection succeeds, the scanner:

   * optionally sends a **service probe**
   * waits for a **banner response**
4. The response is analyzed to **identify the service**.

This allows thousands of ports to be scanned simultaneously.

---

## Supported Service Detection

The scanner detects common services using:

### Known Port Mapping

Examples:

| Port  | Service    |
| ----- | ---------- |
| 21    | FTP        |
| 22    | SSH        |
| 25    | SMTP       |
| 80    | HTTP       |
| 443   | HTTPS      |
| 3306  | MySQL      |
| 5432  | PostgreSQL |
| 6379  | Redis      |
| 27017 | MongoDB    |

---

### Banner Fingerprinting

The scanner also checks banners for common identifiers like:

* `OpenSSH`
* `Apache`
* `nginx`
* `HTTP/1.1`
* `MySQL`
* `PostgreSQL`
* `Redis`

---

## Installation

Compile the program with:

```bash
javac FastPortScanner.java
```

---

## Usage

Basic scan:

```bash
java FastPortScanner <host>
```

Example:

```bash
java FastPortScanner scanme.nmap.org
```

---

### Fast Scan (Top 25 Ports)

```bash
java FastPortScanner <host> --top
```

Example:

```bash
java FastPortScanner 192.168.1.1 --top
```

This scans only the **25 most common ports**, which is significantly faster.

---

## Example Output

```
OPEN PORTS FOUND:

┌────────┬──────────────────┬────────────────────────────────────────────┐
│ Port   │ Service          │ Banner                                     │
├────────┼──────────────────┼────────────────────────────────────────────┤
│ 22     │ ssh              │ SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5    │
│ 80     │ http             │ HTTP/1.1 200 OK                            │
│ 443    │ https            │ HTTP/1.1 400 Bad Request                   │
└────────┴──────────────────┴────────────────────────────────────────────┘

Summary:
► Found 3 open ports
► Scan finished in 2.1s
```

---

## Technical Details

Key technologies used:

* **Java NIO**

  * `SocketChannel`
  * `Selector`
  * `SelectionKey`
* **Non-blocking network I/O**
* **Concurrent connection management**
* **Banner probing**
* **Simple fingerprint matching**

Max concurrent connections:

```
2000
```

---

## Limitations

This tool is intended for **learning and experimentation**.

It does not implement advanced techniques such as:

* SYN scanning
* UDP scanning
* OS detection
* advanced service fingerprinting
* evasion techniques

For professional scanning use tools like **Nmap**.

---

## Disclaimer

This tool is intended for **educational and authorized security testing only**.

Do **not** scan systems without permission.

---

Made with <3 by URDev
