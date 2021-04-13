[![Build Go binaries](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/release.yaml)
[![CodeQL](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/sourcefrenchy/sharesecret/actions/workflows/codeql-analysis.yml)

# sharesecret
A golang mini web service to learn Golang and easily share securely one-time secrets (URL is valid once!) with basic captcha support (although a list of IPs can be provided to skip captcha if need be). 

## Internals
1. Self-managed TLS service (i.e. no need to front with NGINX)
2. A secret is entered and protected by encryption using an Age identity
3. Once encrypted, it is saved in memory in a specific location ranomdly generated (uuid4())
4. The Age identity secret key and location is part of a one-time URL link to provide your peer
   * Yes, it is odd to use a private key publicly but in this case that link leads to the secret anyways.
6. Age identity is discarded (mitigates information disclosure from local privileged access)
7. When accessed, identity is recreated from the private key in the link
8. the second part of the link gives the location and secret can be decrypted and sent back to your peer
9. location and identity removed from memory

## Todo
* better logging and exception management
* support load-balanced service by moving from in memory to some shared storage (e.g. AWS Secrets Manager, etc.)
