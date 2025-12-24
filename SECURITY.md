## Overview

This repository contains documentation and reference implementations for post-quantum cryptographic (PQC) migration strategies. Given the security-critical nature of cryptographic systems, we take vulnerability reports seriously and maintain strict disclosure protocols.

## Supported Versions

The eight-layer PQC framework documentation is actively maintained for the following versions:

| Version | Status | Support Level |
|---------|--------|---------------|
| Latest (main branch) | Active Development | Full Support |
| Tagged Releases | Stable | Security Patches Only |
| Pre-1.0 | Deprecated | No Support |

**Note:** Reference implementations (Python, Go, Rust) are provided for educational and testing purposes only. Production deployments require validated cryptographic libraries (e.g., liboqs, Bouncy Castle PQC, AWS-LC).

## Threat Model & Scope

### In Scope

The following vulnerabilities are considered in-scope for security reports:

**Cryptographic Vulnerabilities:**
- Implementation flaws in PQC algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+, FALCON)
- Side-channel attack vectors (timing, cache, power analysis)
- Key derivation function (KDF) weaknesses
- Random number generator (RNG) entropy deficiencies
- Hybrid encryption mode vulnerabilities (classical + PQC)

**Implementation Security:**
- Memory safety issues (buffer overflows, use-after-free)
- Authentication/authorization bypass in example code
- Insecure cryptographic parameter selection
- Weak default configurations
- Dependency vulnerabilities in reference implementations

**Documentation Security:**
- Incorrect threat modeling guidance
- Misleading migration timeline recommendations
- Insecure architectural patterns
- Compliance framework misalignment (NIST, FIPS, SOC2)

**Infrastructure:**
- Repository access control issues
- CI/CD pipeline security weaknesses
- Malicious code injection via dependencies

### Out of Scope

The following are explicitly out-of-scope:

- Theoretical attacks on NIST-standardized PQC algorithms (report to NIST directly)
- Generic quantum computing research (not implementation-specific)
- Social engineering or phishing attacks
- Physical security of deployment environments
- Third-party library vulnerabilities (report to upstream maintainers)
- Denial of service against documentation hosting
- Typos or grammatical errors (use standard issue tracker)

## Reporting a Vulnerability

### Secure Communication Channels

**CRITICAL:** Do not disclose security vulnerabilities through public GitHub issues, pull requests, or discussions.

**Preferred Method - Encrypted Email:**Contact: security@neurodivergence.works
PGP Key: [To be published at https://neurodivergence.works/.well-known/pgp-key.txt]
Fingerprint: [TBD]
