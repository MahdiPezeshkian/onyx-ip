# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `IsPublic` excludes CGNAT, TEST-NET, documentation, multicast, reserved, and related special-purpose ranges via `net/netip`.

### Added
- Context-aware `LookupISP` with typed errors; `GetISP` remains as a legacy wrapper.


## [0.1.0] - 2026-11-11

### Added

- Initial extraction of ISP detection from `Onyx.Common/isp`.
- IP parse/normalize/classify helpers based on the original detector filter.

[Unreleased]: https://github.com/MahdiPezeshkian/onyx-ip/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MahdiPezeshkian/onyx-ip/releases/tag/v0.1.0
