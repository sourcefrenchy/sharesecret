[![Build Go binaries](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml)
[![CodeQL](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml)

# Secure Secret Sharing Service

## Overview

This Go-based web service is designed for securely sharing secrets in a one-time, secure manner. It leverages the Age encryption tool for robust encryption, providing a unique blend of security and simplicity. Ideal for learning Go and secure communication principles, this project includes basic captcha support for additional security, with an option to bypass captcha for specific IP addresses.

## Key Features

- **Self-Managed TLS**: Implements its own TLS service, eliminating the need for external web servers like NGINX for secure connections.
- **Encryption with Age**: Utilizes Age for encryption, ensuring that secrets are securely protected.
- **One-Time URL Access**: Generates a one-time URL for each secret, making the secret accessible only once for enhanced security.
- **In-Memory Storage**: Temporarily stores encrypted secrets in memory with a unique location identifier, reducing the risk of disk-based vulnerabilities.
- **Captcha Verification**: Incorporates basic captcha validation to prevent automated access, with allowances for IP-based exemptions.

## How It Works

1. A user submits a secret, which is then encrypted using an Age identity.
2. The encrypted secret is stored in memory, and a unique URL is generated. This URL includes the Age identity's secret key and a unique identifier for the secret's location.
3. The URL is shared with the intended recipient. Accessing the URL allows the recipient to decrypt and retrieve the secret.
4. Upon access, the secret's location and Age identity are purged from memory, ensuring the secret cannot be accessed again.

## Todo
* Improve logging and exception management.
* Support load-balanced service by moving from in-memory to some shared storage (e.g., AWS Secrets Manager, etc.).
