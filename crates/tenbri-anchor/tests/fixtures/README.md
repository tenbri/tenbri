# RFC 3161 fixtures

`openssl-rsa.tsr` is an RFC 3161 response made by OpenSSL 3 (`openssl ts -reply`, SHA-256,
certificate requested) over `openssl-text.txt`, by an RSA-2048 TSA certificate issued by an
intermediate CA (carried in the token) under `openssl-root.pem`. The private keys were thrown away;
the certificates are valid for 100 years. Tenbri's test TSA makes ECDSA tokens, so this one covers
the RSA path and a token Tenbri did not make. CC0, as spec/vectors/.
