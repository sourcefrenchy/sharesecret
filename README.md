[![Build Go binaries](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml)
[![CodeQL](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml)

# sharesecret
A Golang mini web service designed to learn Golang and securely share secrets once (the URL is valid only once!) with basic captcha support (although a list of IPs can be provided to skip captcha if needed).

## Internals
1. Self-managed TLS service (i.e., no need to front with NGINX).
2. A secret is entered and protected by encryption using an Age identity.
3. Once encrypted, it is saved in memory in a specific location randomly generated (`uuid4()`).
4. The Age identity secret key and location are part of a one-time URL link to provide to your peer.
    * Yes, it is odd to use a private key publicly, but in this case, that link leads to the secret anyway.
5. Age identity is discarded (mitigates information disclosure from local privileged access).
6. When accessed, the identity is recreated from the private key in the link.
7. The second part of the link gives the location, and the secret can be decrypted and sent back to your peer.
8. The location and identity are removed from memory.

## Todo
* Improve logging and exception management.
* Support load-balanced service by moving from in-memory to some shared storage (e.g., AWS Secrets Manager, etc.).
