# onyx-ip

[![Go Version](https://img.shields.io/badge/go-1.27-00ADD8.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

IP address helpers and optional ISP detection.

## Installation

```bash
go get github.com/MahdiPezeshkian/onyx-ip@latest
```

```go
import "github.com/MahdiPezeshkian/onyx-ip"
```

## IsPublic policy

`IsPublic` means a **globally routable unicast** address suitable for external
lookup — not merely “not RFC1918”.

Rejected examples include private, loopback, link-local, unique-local,
multicast, unspecified, CGNAT (`100.64.0.0/10`), TEST-NET, benchmarking,
IANA reserved, and documentation ranges (`192.0.2.0/24`, `2001:db8::/32`, …).

`IsPrivateOrLocal` keeps the narrower historical filter (private/loopback/
unspecified/link-local only). Prefer `IsPublic` for routability decisions.

## ISP lookup

Preferred API:

```go
org, err := ip.NewIPInfoDetector(nil).LookupISP(ctx, clientIP)
```

Legacy `GetISP` still returns `""` on failure for compatibility.

Classification methods never perform network I/O.

## License

MIT — see [LICENSE](LICENSE).
