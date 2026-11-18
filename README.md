# JWT Decoder (Spring Security console app)

A small Java 17+ console application that decodes JWTs with Spring Security's
`org.springframework.security.oauth2.jwt` package (`Jwt`, `JwtDecoder`,
`NimbusJwtDecoder`, `JwtDecoders`, `MappedJwtClaimSetConverter`).

Versions come from `spring-boot-starter-parent` 3.4.5, which manages
Spring Security 6.4.5 and Spring Framework 6.2.6. To move to another Boot
release, change only the parent version in `pom.xml`.

## Build

```bash
mvn clean package
```

This produces a runnable jar at `target/jwt-decoder.jar`.

## Run

Decode only (the signature is **not** checked):

```bash
java -jar target/jwt-decoder.jar eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Decode and verify:

```bash
# HMAC (HS256/384/512)
java -jar target/jwt-decoder.jar --secret "my-256-bit-secret-my-256-bit-secret" <token>

# RSA public key (PEM, "BEGIN PUBLIC KEY")
java -jar target/jwt-decoder.jar --public-key public.pem <token>

# JWK Set endpoint
java -jar target/jwt-decoder.jar --jwks https://idp.example.com/.well-known/jwks.json <token>

# OpenID Connect issuer (keys discovered, 'iss' checked)
java -jar target/jwt-decoder.jar --issuer https://accounts.google.com <token>
```

Other options:

| Option | Meaning |
|---|---|
| `--secret-base64 <b64>` | HMAC secret given in Base64 |
| `--skip-exp` | Verify the signature but accept expired / not-yet-valid tokens |
| *(no token)* | Read the token from standard input, e.g. `echo $TOKEN \| java -jar target/jwt-decoder.jar` |

A leading `Bearer ` is stripped automatically, so you can paste an
`Authorization` header value directly.

Or run without packaging:

```bash
mvn -q compile exec:java -Dexec.args="--secret mysecret... <token>"
```

## Output

```
=== Header ===
{
  "alg": "HS256",
  "typ": "JWT"
}

=== Claims ===
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022  /* 2018-01-18 01:30:22 UTC */
}

=== Summary ===
Signature  : NOT VERIFIED (no key supplied)
Algorithm  : HS256
Subject    : 1234567890
Issued at  : 2018-01-18 01:30:22 UTC (1516239022)
```

Exit code is `0` on success and `1` if the token is malformed, the signature
does not match, or validation (e.g. expiry) fails.

## Notes

- HMAC secrets must be at least 256 bits (32 bytes) for HS256; Nimbus rejects shorter keys.
- `--public-key` supports RSA keys (RS256/384/512, PS256/384/512). For EC keys, use `--jwks`.
- Encrypted tokens (JWE) cannot be decoded without the decryption key.
