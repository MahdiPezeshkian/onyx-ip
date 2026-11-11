# onyx-ip

[![Go Version](https://img.shields.io/badge/go-1.27-00ADD8.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

IP address helpers and optional ISP detection. Extracted from
`Onyx.Common/isp`, with classification helpers factored out of the original
detector filter.

## Installation

```bash
go get github.com/MahdiPezeshkian/onyx-ip@v0.1.0
```

## Import path

```go
import "github.com/MahdiPezeshkian/onyx-ip"
```

Package name: `ip`

## Basic usage

```go
if !ip.IsPublic(clientIP) {
	return
}
org := ip.NewIPInfoDetector(nil).GetISP(clientIP)
```

## Public API overview

| API | Purpose |
|---|---|
| `Parse` / `Normalize` / `IsValid` | Parse and canonicalize IPv4/IPv6 |
| `IsPublic` / `IsPrivateOrLocal` | Classification used by ISP lookup |
| `Detector` | ISP resolution interface |
| `NewIPInfoDetector` | ipinfo.io-backed detector |
| `NewIPInfoDetectorWithBaseURL` | Same detector with a custom base URL (tests/proxies) |

## Design decisions

- Prefer `net` from the standard library for parsing and classification.
- ISP lookup remains optional and network-backed; private/local IPs return `""`
  without making an HTTP call.
- No broad networking framework or CIDR algebra was invented beyond what the
  original detector needed.

## Dependencies

None beyond the Go standard library (`net`, `net/http`, `encoding/json`).

## Limitations

- ISP detection depends on the public ipinfo.io API and network availability.
- Failures return an empty string rather than an error (historical behavior).
- Does not ship an offline IP-to-ISP database.

## License

MIT — see [LICENSE](LICENSE).
