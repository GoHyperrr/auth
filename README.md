# auth — Hyperrr Pluggable Authentication Module

[![Go Reference](https://pkg.go.dev/badge/github.com/GoHyperrr/auth.svg)](https://pkg.go.dev/github.com/GoHyperrr/auth)
[![Go Coverage](https://github.com/GoHyperrr/auth/wiki/coverage.svg)](https://raw.githack.com/wiki/GoHyperrr/auth/coverage.html)

This repository contains the pluggable authorization providers for the Hyperrr engine, including standard Email/Password, JWT verification, and secure API Key generation.

---

## 🔒 Active Providers

* **Standard Email/Password**: Secure user registrations and login verifications using cryptographic hashing (`bcrypt`).
* **JWT (JSON Web Token)**: Standard claims verification and stateless sessions.
* **API Keys**: Randomly generated cryptographically secure API tokens for Model Context Protocol (MCP) gateways and AI agent programmatic access.

---

## 🛠️ Usage

This module is imported dynamically by the core Hyperrr engine and exposes CLI commands and middlewares.

To learn more about how to develop authentication providers or configure them, see the [Hyperrr Developer Guide](https://github.com/GoHyperrr/hyperrr/blob/main/developer.md).
