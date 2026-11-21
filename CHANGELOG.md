# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Release automation for building distributions, publishing packages, and creating GitHub releases from version tags.
- Release documentation describing the versioning and publishing workflow.

## [2.0.1] - 2026-11-21

### Added
- Hybrid evidence-based verification pipeline improvements, including CDP runtime hooks, AST/DFG slicing, framework sink suppression, context-aware mutation, and execution-oracle verification.
- Extended recon, fuzzing, endpoint discovery, and detection coverage across JavaScript intelligence, path/parameter wordlists, payloads, and sink tracking.
- Additional analysis modules and scan-pipeline integration for broader XSS and client-side security coverage.

### Changed
- Hardened stored-XSS verification and surfaced static leads as explicit low-confidence findings where runtime execution is not confirmed.
- Improved report filtering and delivery of analyzer-generated candidates through the scanning pipeline.

### Notes
- For a detailed commit-by-commit history, see the repository's Git history.

[Unreleased]: https://github.com/gl1tch0x1/xoxss/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/gl1tch0x1/xoxss/releases/tag/v2.0.1
