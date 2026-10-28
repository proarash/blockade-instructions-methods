# Edge IP Scanning & Censorship Circumvention Architecture

## 1. Edge IP Scanning Mechanics (Cloudflare & Fastly)

### 1.1 Why CDN Edge Scanning Works
CDNs operate multi-tenant Anycast networks where thousands of domains share identical edge IP pools. In restrictive network environments, state firewalls (DPI) rarely block an entire ASN at once due to collateral enterprise damage. Instead, they throttle, inject TCP RST packets, or null-route specific `/24` or `/32` IP subnets.

Edge scanning bypasses local DNS resolvers and queries edge IPs directly to measure three metrics:
1. **TCP Reachability:** Port 443 TCP handshake completion time without packet drops.
2. **TLS Handshake Verification:** Successful negotiation of TLS 1.3 using a known CDN-hosted SNI.
3. **HTTP/2 or HTTP/3 Validation:** Round-trip latency and download throughput via real edge endpoints (e.g., Cloudflare's `/cdn-cgi/trace` or Fastly diagnostic paths).

---

### 1.2 Target Edge Verification Endpoints

To scan an edge IP, you must pass an SNI and `Host` header that the target CDN's edge acknowledges:

| CDN Provider | Official Published IP Ranges | Verified Target SNI / Host | Valid Validation Path |
| :--- | :--- | :--- | :--- |
| **Cloudflare** | `https://www.cloudflare.com/ips-v4` | `speed.cloudflare.com` or `cloudflare.com` | `/__down?bytes=1000` or `/cdn-cgi/trace` |
| **Fastly** | `https://api.fastly.com/public-ip-list` | `fastly.com` or `www.github.com` | `/` |
| **ArvanCloud** | `https://www.arvancloud.ir/en/ips.txt` | Your own domain proxied through ArvanCloud | `/` (any path on your domain) |

---

### 1.3 High-Performance Go Scanner Implementation

This concurrent scanner tests custom CIDR ranges by executing raw TCP connections followed by SNI-injected TLS handshakes and lightweight HTTP requests.

```go
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Target Settings
const targetCDN = "cloudflare" // or "fastly"

type cdnConfig struct {
	SNI   string
	Path  string
	CIDRs []string
}

var cdnConfigs = map[string]cdnConfig{
	"cloudflare": {
		SNI:  "speed.cloudflare.com",
		Path: "/cdn-cgi/trace",
		// Source: https://www.cloudflare.com/ips-v4 (fetched 2026-10-28)
		CIDRs: []string{
			"173.245.48.0/20",
			"103.21.244.0/22",
			"103.22.200.0/22",
			"103.31.4.0/22",
			"141.101.64.0/18",
			"108.162.192.0/18",
			"190.93.240.0/20",
			"188.114.96.0/20",
			"197.234.240.0/22",
			"198.41.128.0/17",
			"162.158.0.0/15",
			"104.16.0.0/13",
			"104.24.0.0/14",
			"172.64.0.0/13",
			"131.0.72.0/22",
		},
	},
	"fastly": {
		SNI:  "fastly.com",
		Path: "/",
		// Source: https://api.fastly.com/public-ip-list (fetched 2026-10-28)
		CIDRs: []string{
			"23.235.32.0/20",
			"43.249.72.0/22",
			"90.98.0.0/17",
			"90.98.128.0/18",
			"103.244.50.0/24",
			"103.245.222.0/23",
			"103.245.224.0/24",
			"104.156.80.0/20",
			"140.248.64.0/18",
			"140.248.128.0/17",
			"146.75.0.0/17",
			"151.101.0.0/16",
			"157.52.64.0/18",
			"167.82.0.0/17",
			"167.82.128.0/20",
			"167.82.160.0/20",
			"167.82.224.0/20",
			"172.111.64.0/18",
			"185.31.16.0/22",
			"199.27.72.0/21",
			"199.232.0.0/16",
		},
	},
}

const (
	timeout    = 1500 * time.Millisecond
	maxWorkers = 64
)

type result struct {
	IP    string
	TCPms float64
	TLSms float64
}

// scanEdgeIP measures TCP connect, TLS handshake, and basic HTTP response time.
func scanEdgeIP(ip, host, path string) (*result, bool) {
	start := time.Now()

	// Step 1: Raw TCP Connection
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return nil, false
	}
	tcpRTT := float64(time.Since(start).Microseconds()) / 1000
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	// Step 2: TLS Handshake with designated SNI
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: host})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}
	tlsRTT := float64(time.Since(start).Microseconds()) / 1000

	// Step 3: Lightweight HTTP/1.1 Probe
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: EdgeProbe/2.0\r\nConnection: close\r\n\r\n", path, host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, false
	}
	buf := make([]byte, 256)
	n, _ := tlsConn.Read(buf)
	data := string(buf[:n])

	for _, code := range []string{"200", "301", "302", "403"} {
		if strings.Contains(data, code) {
			return &result{IP: ip, TCPms: tcpRTT, TLSms: tlsRTT}, true
		}
	}
	return nil, false
}

func main() {
	cfg := cdnConfigs[targetCDN]
	host, path := cfg.SNI, cfg.Path

	// Generate test IPs (sample 1 host per /24 to conserve local socket limits)
	var scanIPs []string
	for _, cidr := range cfg.CIDRs {
		prefix := netip.MustParsePrefix(cidr).Masked()
		addr := prefix.Addr()
		for i := 0; i < 20 && prefix.Contains(addr); i++ {
			scanIPs = append(scanIPs, addr.Next().String()) // .1 of each /24
			b := addr.As4()
			b[2]++
			if b[2] == 0 {
				b[1]++
			}
			addr = netip.AddrFrom4(b)
		}
	}

	fmt.Printf("[*] Scanning %d sampled edge IPs against %s...\n", len(scanIPs), host)

	jobs := make(chan string)
	results := make(chan *result)
	var wg sync.WaitGroup
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if r, ok := scanEdgeIP(ip, host, path); ok {
					results <- r
				}
			}
		}()
	}
	go func() {
		for _, ip := range scanIPs {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var clean []*result
	for r := range results {
		fmt.Printf("[+] CLEAN: %-16s | TCP: %5.1fms | TLS: %5.1fms\n", r.IP, r.TCPms, r.TLSms)
		clean = append(clean, r)
	}

	sort.Slice(clean, func(i, j int) bool { return clean[i].TLSms < clean[j].TLSms })
	fmt.Println("\n--- TOP CLEAN EDGE NODES ---")
	for i, r := range clean {
		if i == 10 {
			break
		}
		fmt.Printf("%s\t(Total RTT: %.1fms)\n", r.IP, r.TLSms)
	}
}
```

---

### 1.4 ArvanCloud Edge Scanner (VPS Domain via ArvanEdge)

ArvanCloud is a domestic Iranian CDN, so its edge nodes usually stay reachable during international blockades. If your VPS domain is added to ArvanCloud with the CDN proxy enabled (DNS record pointing to the VPS origin), you can connect to any reachable Arvan edge IP using **your own domain** as SNI and `Host`, and the edge forwards traffic to your VPS.

Unlike Cloudflare and Fastly, Arvan publishes many small ranges (`/27`–`/30`), so this scanner tests **every host** in each range instead of sampling one IP per `/24`. Pass your domain with `-domain`; an IP is clean when it completes TLS for your domain and the response carries ArvanCloud's `Server` header.

> **Caveat:** ArvanCloud terminates TLS inside Iran, so the edge can see your decrypted traffic (see section 4). Run an inner encrypted protocol (e.g. VLESS or Trojan over WebSocket/gRPC) through it rather than plain HTTP.

```go
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source: https://www.arvancloud.ir/en/ips.txt (fetched 2026-10-28)
var arvanCIDRs = []string{
	"185.143.232.0/22",
	"188.229.116.16/30",
	"94.101.182.0/27",
	"2.144.3.128/28",
	"37.32.16.0/27",
	"37.32.17.0/27",
	"37.32.18.0/27",
	"37.32.19.0/27",
	"185.215.232.0/22",
	"178.131.120.48/28",
	"94.101.183.0/28",
	"78.157.36.112/28",
	"95.38.61.80/28",
	"193.24.119.0/29",
}

const (
	timeout    = 2 * time.Second
	maxWorkers = 64
)

type result struct {
	IP    string
	TCPms float64
	TLSms float64
}

// scanArvanIP connects to an edge IP using the VPS domain as SNI/Host and checks
// that the response was served by ArvanCloud.
func scanArvanIP(ip, domain, path string) (*result, bool) {
	start := time.Now()

	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return nil, false
	}
	tcpRTT := float64(time.Since(start).Microseconds()) / 1000
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: domain})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return nil, false
	}
	tlsRTT := float64(time.Since(start).Microseconds()) / 1000

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: EdgeProbe/2.0\r\nConnection: close\r\n\r\n", path, domain)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return nil, false
	}
	buf := make([]byte, 1024)
	n, _ := tlsConn.Read(buf)
	data := strings.ToLower(string(buf[:n]))

	if strings.HasPrefix(data, "http/1.1 ") && strings.Contains(data, "server: arvancloud") {
		return &result{IP: ip, TCPms: tcpRTT, TLSms: tlsRTT}, true
	}
	return nil, false
}

func main() {
	domain := flag.String("domain", "", "your VPS domain proxied through ArvanCloud (required)")
	path := flag.String("path", "/", "request path on your domain")
	flag.Parse()
	if *domain == "" {
		fmt.Println("usage: arvanscan -domain vpn.example.com [-path /]")
		return
	}

	// Enumerate every usable host in each range (ranges are small)
	var scanIPs []string
	for _, cidr := range arvanCIDRs {
		prefix := netip.MustParsePrefix(cidr).Masked()
		for addr := prefix.Addr().Next(); prefix.Contains(addr.Next()); addr = addr.Next() {
			scanIPs = append(scanIPs, addr.String())
		}
	}

	fmt.Printf("[*] Scanning %d ArvanCloud edge IPs against %s...\n", len(scanIPs), *domain)

	jobs := make(chan string)
	results := make(chan *result)
	var wg sync.WaitGroup
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if r, ok := scanArvanIP(ip, *domain, *path); ok {
					results <- r
				}
			}
		}()
	}
	go func() {
		for _, ip := range scanIPs {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var clean []*result
	for r := range results {
		fmt.Printf("[+] CLEAN: %-16s | TCP: %5.1fms | TLS: %5.1fms\n", r.IP, r.TCPms, r.TLSms)
		clean = append(clean, r)
	}

	sort.Slice(clean, func(i, j int) bool { return clean[i].TLSms < clean[j].TLSms })
	fmt.Println("\n--- TOP CLEAN ARVAN EDGE NODES ---")
	for i, r := range clean {
		if i == 10 {
			break
		}
		fmt.Printf("%s\t(Total RTT: %.1fms)\n", r.IP, r.TLSms)
	}
}
```

Use the fastest clean IP as the client's server address while keeping your domain as SNI/`Host` in the client config (e.g. Xray/V2Ray `address: <clean IP>`, `serverName`/`host: <your domain>`).

---

## 2. Understanding Domain Fronting

### 2.1 Mechanics (SNI vs. HTTP `Host`)
Domain Fronting exploits the two-tier structure of HTTPS communication:
1. **Outer Transport (Unencrypted / Inspectable):** During the initial TLS handshake, the client sends a `Server Name Indication` (SNI). A network firewall inspecting traffic sees only the SNI and the destination IP.
2. **Inner Application (Encrypted inside TLS):** Once the TLS tunnel is established, the client issues the actual HTTP request containing a `Host` header.

```
Client                                      CDN Edge                          Origin Server
  │                                            │                                    │
  ├─── 1. TLS ClientHello ────────────────────>│                                    │
  │    SNI: "allowed-front.com"                │ (Censor sees allowed-front.com)    │
  │<── 2. TLS Certificate & Completion ────────┤                                    │
  │                                            │                                    │
  ├─── 3. Encrypted HTTP Request ─────────────>│                                    │
  │    GET /tunnel HTTP/1.1                    │                                    │
  │    Host: "blocked-origin.com"              │ Decrypts payload, inspects Host    │
  │                                            ├──── 4. Forwards traffic ──────────>│
  │                                            │                                    │
```

If `allowed-front.com` and `blocked-origin.com` are both hosted on the same CDN or cloud provider, the edge routes traffic based on the internal `Host` header, circumventing the SNI inspection.

### 2.2 Why Classic Domain Fronting Failed
* **Provider Blocking:** Major providers (Google Cloud, AWS CloudFront, Cloudflare) disabled cross-account domain fronting by enforcing strict **SNI/Host header parity checks**. If the SNI domain does not match the HTTP `Host` header domain on that tenant account, the edge returns `421 Misdirected Request` or `403 Forbidden`.
* **ESNI / ECH Limitations:** Encrypted Client Hello (ECH) replaces plaintext SNI, but censors drop ECH outer handshakes outright unless explicitly whitelisted.

---

## 3. Circumvention Methods Under Severe Blockades (Whitelists)

When network authorities switch to an **Exclusive Whitelist** (e.g., only local intranet or specific foreign platforms like `google.com` resolve and pass traffic), standard open-port proxies immediately fail. The following technical strategies address this scenario:

### 3.1 VLESS with REALITY (SNI Impersonation)
Instead of relying on a CDN, **Reality** operates directly between your client and your foreign VPS.
* **Mechanism:** Your VPS server intercepts incoming TLS connections and proxies the TLS handshake directly from an allowed target site (e.g., `google.com` or an unblocked enterprise portal).
* **Why it beats DPI:** Censors inspecting the handshake see genuine cryptographic signatures and valid certificates belonging to `google.com`. Once the client validates the server using a pre-shared Reality public key, the connection pivots inside the session without completing the standard server certificate validation against a domain you own.
* **Requirements:** An external VPS and a client supporting Xray-core or Sing-box.

---

### 3.2 ShadowTLS (Session Hijacking / Co-existence)
ShadowTLS isolates the TLS handshake from the actual payload transport:
1. When the client initiates a connection to the ShadowTLS server, the server forwards the handshake to an official whitelisted endpoint (e.g., `google.com`).
2. The ISP sees a 100% valid TLS 1.3 handshake with Google's servers.
3. Once the handshake finishes, the client injects an authenticated HMAC challenge. The ShadowTLS server detects this challenge, detaches from Google's endpoint, and routes subsequent traffic to your backend proxy (e.g., Shadowsocks or VLESS).

---

### 3.3 Tor Pluggable Transports
When direct IP routing to the exterior is severed, specific pluggable transports mask communication patterns:

* **Snowflake (WebRTC Piercing):**
  * Channels traffic over **WebRTC** (the protocol powering Google Meet, Discord, and browser voice calls).
  * It routes packets through transient volunteer proxies running in desktop browsers worldwide.
  * Censors cannot block Snowflake without breaking standard peer-to-peer enterprise video calling infrastructure.
* **WebTunnel (HTTP/2 Reverse Proxy Masking):**
  * Bridges traffic inside standard HTTP/2 sessions configured on genuine web servers.
  * The proxy path is indistinguishable from standard HTTPS web browsing to a legitimate website.
* **meek (Azure CDN Fronting):**
  * Uses Domain Fronting via Microsoft Azure edge networks (`ajax.aspnetcdn.com`).
  * Because Microsoft services are deeply integrated into enterprise Windows environments, blocking these edge networks incurs heavy operational costs for local businesses.

---

### 3.4 Packet Manipulation / Anti-DPI Engines
When firewalls perform Layer 7 stateful packet inspection on standard outgoing TCP/IP frames, local anti-DPI software (e.g., **Zapret**, **GoodbyeDPI**, **ByeDPI**) can run directly on the client:
* **TCP Window Fragmentation:** Splitting the HTTP request or TLS `ClientHello` across tiny fragments (e.g., dividing the SNI across 2 separate TCP packets). Stateful DPI buffers often fail to reassemble out-of-order or fragmented headers and pass the packets uninspected.
* **Fake Out-of-Band Packets:** Transmitting a spoofed TCP RST or low-TTL packet with invalid checksums. The intermediate censor firewall drops the connection tracking state, while the destination server ignores the invalid packet and accepts the real stream.

---

### 3.5 Covert Channels (Extreme National Intranet Mode)
If all TCP/UDP traffic to foreign IP blocks is completely severed at the core border gateway (IXP):

| Protocol | Transport | How It Operates | Limitations |
| :--- | :--- | :--- | :--- |
| **DNS Tunneling** (`dnscat2`, `iodine`) | Port 53 UDP | Encapsulates IP packets inside standard recursive DNS queries. As long as domestic recursive resolvers resolve external root domains, data leaks through. | Extremely slow (10–100 kbps); high latency. |
| **ICMP Tunneling** (`ptunnel-ng`, `hans`) | IP Protocol 1 (Ping) | Wraps arbitrary TCP payload data inside ICMP Echo/Reply packets. Works if external ping is unblocked while TCP 80/443 is filtered. | Dropped by most modern tier-1 ISPs. |
| **QUIC / UDP Obfuscation** (`Hysteria 2`, `TUIC`) | HTTP/3 UDP | Employs custom congestion control over UDP with randomized packet paddings and port hopping to prevent UDP rate-limiting. | Aggressively throttled if local ISPs enforce blanket UDP blocks. |

---

## 4. Practical Architecture Summary

If you have **no external VPS**:
* Rely on **Tor Snowflake** (leverages WebRTC) or public **ArgoVPN Bridges**.

If you obtain an **external VPS**:
* Deploy **VLESS + REALITY** or **ShadowTLS** targeting a valid unblocked SNI (such as `google.com` or local whitelisted resources).
* Avoid routing tunnel traffic through domestic reverse proxies or unencrypted CDN front ends that terminate TLS in domestic data centers.