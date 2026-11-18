package com.example.jwtdecoder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Console application that decodes a JWT using Spring Security's
 * {@code org.springframework.security.oauth2.jwt} package.
 *
 * <p>Without a key it only decodes (signature NOT verified). With
 * {@code --secret}, {@code --public-key}, {@code --jwks} or {@code --issuer}
 * it decodes through a {@link NimbusJwtDecoder}, which verifies the signature
 * and (unless {@code --skip-exp} is given) the exp/nbf timestamps.
 */
public final class JwtDecoderApp {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault());

    private static final String USAGE = """
            Usage: java -jar jwt-decoder.jar [options] [token]

            Decodes a JWT and prints its header and claims. If no token is given,
            it is read from standard input. A leading "Bearer " is ignored.

            Verification options (pick one; without any, the signature is NOT checked):
              --secret <text>          HMAC secret (HS256/HS384/HS512), as plain text
              --secret-base64 <b64>    HMAC secret, Base64-encoded
              --public-key <file.pem>  RSA public key in PEM format (RS256/RS384/RS512/PS*)
              --jwks <url>             JWK Set URI, e.g. https://idp.example.com/.well-known/jwks.json
              --issuer <url>           OpenID Connect issuer; keys are discovered and 'iss' is checked

            Other options:
              --skip-exp               Accept expired / not-yet-valid tokens when verifying
              -h, --help               Show this help
            """;

    private JwtDecoderApp() {
    }

    public static void main(String[] args) {
        try {
            Options options = Options.parse(args);
            if (options.help) {
                System.out.println(USAGE);
                return;
            }
            String token = normalise(options.token != null ? options.token : readStdin());
            if (token.isEmpty()) {
                fail("No token supplied.\n\n" + USAGE);
            }

            Map<String, Object> rawHeader = parseUnverified(token).getHeader().toJSONObject();
            String alg = String.valueOf(rawHeader.get("alg"));

            Jwt jwt;
            String verification;
            JwtDecoder decoder = buildDecoder(options, alg);
            if (decoder == null) {
                jwt = decodeWithoutVerification(token);
                verification = "NOT VERIFIED (no key supplied)";
            } else {
                jwt = decoder.decode(token);
                verification = "VALID signature (" + alg + ")"
                        + (options.skipExp ? ", timestamps not checked" : ", timestamps valid");
            }

            print(jwt, verification);
        } catch (JwtValidationException ex) {
            String reasons = ex.getErrors().stream()
                    .map(OAuth2Error::getDescription)
                    .collect(Collectors.joining("; "));
            fail("Token failed validation: " + reasons);
        } catch (JwtException ex) {
            fail("Could not decode token: " + rootMessage(ex));
        } catch (IllegalArgumentException ex) {
            fail(ex.getMessage());
        } catch (Exception ex) {
            fail("Error: " + rootMessage(ex));
        }
    }

    // ------------------------------------------------------------------ decoding

    /** Builds a verifying Spring {@link JwtDecoder}, or returns null when no key was supplied. */
    private static JwtDecoder buildDecoder(Options o, String alg) throws Exception {
        NimbusJwtDecoder decoder;
        OAuth2TokenValidator<Jwt> relaxedValidator = jwt -> OAuth2TokenValidatorResult.success();

        if (o.secret != null) {
            MacAlgorithm mac = MacAlgorithm.from(alg);
            if (mac == null) {
                throw new IllegalArgumentException(
                        "Token is signed with " + alg + ", which is not an HMAC algorithm; --secret cannot verify it.");
            }
            SecretKeySpec key = new SecretKeySpec(o.secret, mac.getName().replace("HS", "HmacSHA"));
            decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(mac).build();
        } else if (o.publicKeyFile != null) {
            SignatureAlgorithm sig = requireSignatureAlgorithm(alg);
            decoder = NimbusJwtDecoder.withPublicKey(readRsaPublicKey(o.publicKeyFile))
                    .signatureAlgorithm(sig).build();
        } else if (o.jwksUri != null) {
            SignatureAlgorithm sig = requireSignatureAlgorithm(alg);
            decoder = NimbusJwtDecoder.withJwkSetUri(o.jwksUri).jwsAlgorithm(sig).build();
        } else if (o.issuer != null) {
            decoder = JwtDecoders.fromIssuerLocation(o.issuer);
            relaxedValidator = new DelegatingOAuth2TokenValidator<>(new JwtIssuerValidator(o.issuer));
        } else {
            return null;
        }

        if (o.skipExp) {
            decoder.setJwtValidator(relaxedValidator);
        }
        return decoder;
    }

    /**
     * Decodes without checking the signature, then builds a Spring {@link Jwt} using the same
     * claim conversion that {@link NimbusJwtDecoder} applies (exp/iat/nbf become {@link Instant}s,
     * aud becomes a list, and so on).
     */
    private static Jwt decodeWithoutVerification(String token) {
        JWT parsed = parseUnverified(token);
        if (parsed instanceof EncryptedJWT) {
            throw new IllegalArgumentException("This is an encrypted JWT (JWE); it cannot be read without the decryption key.");
        }
        Map<String, Object> headers = new LinkedHashMap<>(parsed.getHeader().toJSONObject());
        Map<String, Object> claims;
        try {
            claims = parsed.getJWTClaimsSet().getClaims();
        } catch (ParseException ex) {
            throw new IllegalArgumentException("Token payload is not a valid JSON claims set: " + ex.getMessage());
        }
        Map<String, Object> converted = MappedJwtClaimSetConverter
                .withDefaults(Collections.emptyMap())
                .convert(claims);

        return Jwt.withTokenValue(token)
                .headers(h -> h.putAll(headers))
                .claims(c -> c.putAll(converted))
                .build();
    }

    private static JWT parseUnverified(String token) {
        try {
            return JWTParser.parse(token);
        } catch (ParseException ex) {
            throw new IllegalArgumentException("Not a well-formed JWT: " + ex.getMessage());
        }
    }

    private static SignatureAlgorithm requireSignatureAlgorithm(String alg) {
        SignatureAlgorithm sig = SignatureAlgorithm.from(alg);
        if (sig == null) {
            throw new IllegalArgumentException(
                    "Token is signed with " + alg + ", which is not an asymmetric signature algorithm.");
        }
        return sig;
    }

    private static RSAPublicKey readRsaPublicKey(Path pem) throws Exception {
        String base64 = Files.readString(pem)
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        if (base64.contains("-----")) {
            throw new IllegalArgumentException(
                    "Expected an X.509 'BEGIN PUBLIC KEY' PEM file (convert with: openssl rsa -pubin -in key.pem -RSAPublicKey_in -out out.pem).");
        }
        byte[] der = Base64.getDecoder().decode(base64);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    // ------------------------------------------------------------------ output

    private static void print(Jwt jwt, String verification) {
        System.out.println("=== Header ===");
        System.out.println(toJson(jwt.getHeaders(), 0));
        System.out.println();
        System.out.println("=== Claims ===");
        System.out.println(toJson(jwt.getClaims(), 0));
        System.out.println();
        System.out.println("=== Summary ===");
        row("Signature", verification);
        row("Algorithm", String.valueOf(jwt.getHeaders().get("alg")));
        row("Subject", jwt.getSubject());
        row("Issuer", jwt.getClaimAsString(JwtClaimNames.ISS));
        row("Audience", jwt.getAudience() == null ? null : String.join(", ", jwt.getAudience()));
        row("JWT ID", jwt.getId());
        row("Issued at", time(jwt.getIssuedAt()));
        row("Not before", time(jwt.getNotBefore()));
        if (jwt.getExpiresAt() != null) {
            row("Expires at", time(jwt.getExpiresAt()) + expiryNote(jwt.getExpiresAt()));
        }
    }

    private static void row(String label, String value) {
        if (value != null) {
            System.out.printf("%-11s: %s%n", label, value);
        }
    }

    private static String time(Instant instant) {
        return instant == null ? null : TIME_FORMAT.format(instant) + " (" + instant.getEpochSecond() + ")";
    }

    private static String expiryNote(Instant exp) {
        if (exp == null) {
            return "";
        }
        return Instant.now().isAfter(exp) ? "  ** EXPIRED **" : "  (still valid)";
    }

    /** Minimal pretty-printer so the app needs no JSON library beyond what Spring Security brings. */
    private static String toJson(Object value, int indent) {
        String pad = "  ".repeat(indent);
        String inner = "  ".repeat(indent + 1);
        if (value == null) {
            return "null";
        }
        if (value instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                return "{}";
            }
            StringBuilder sb = new StringBuilder("{\n");
            Iterator<? extends Map.Entry<?, ?>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> e = it.next();
                sb.append(inner).append(quote(String.valueOf(e.getKey()))).append(": ")
                        .append(toJson(e.getValue(), indent + 1))
                        .append(it.hasNext() ? ",\n" : "\n");
            }
            return sb.append(pad).append('}').toString();
        }
        if (value instanceof Collection<?> list) {
            if (list.isEmpty()) {
                return "[]";
            }
            return list.stream().map(v -> inner + toJson(v, indent + 1))
                    .collect(Collectors.joining(",\n", "[\n", "\n" + pad + "]"));
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof Instant instant) {
            return instant.getEpochSecond() + "  /* " + TIME_FORMAT.format(instant) + " */";
        }
        return quote(value.toString());
    }

    private static String quote(String s) {
        return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + '"';
    }

    // ------------------------------------------------------------------ helpers

    private static String normalise(String token) {
        String t = token == null ? "" : token.trim();
        if (t.regionMatches(true, 0, "Bearer ", 0, 7)) {
            t = t.substring(7).trim();
        }
        return t;
    }

    private static String readStdin() throws IOException {
        if (System.console() != null) {
            System.err.print("Paste JWT and press Enter: ");
        }
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        return in.lines().collect(Collectors.joining()).trim();
    }

    private static String rootMessage(Throwable t) {
        Throwable root = t;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String msg = root == t ? t.getMessage() : t.getMessage() + " (" + root.getMessage() + ")";
        return msg == null ? t.getClass().getSimpleName() : msg;
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(1);
    }

    // ------------------------------------------------------------------ CLI parsing

    private static final class Options {
        String token;
        byte[] secret;
        Path publicKeyFile;
        String jwksUri;
        String issuer;
        boolean skipExp;
        boolean help;

        static Options parse(String[] args) {
            Options o = new Options();
            int keySources = 0;
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "-h", "--help" -> o.help = true;
                    case "--skip-exp" -> o.skipExp = true;
                    case "--secret" -> {
                        o.secret = next(args, ++i, a).getBytes(StandardCharsets.UTF_8);
                        keySources++;
                    }
                    case "--secret-base64" -> {
                        o.secret = Base64.getDecoder().decode(next(args, ++i, a));
                        keySources++;
                    }
                    case "--public-key" -> {
                        o.publicKeyFile = Path.of(next(args, ++i, a));
                        keySources++;
                    }
                    case "--jwks" -> {
                        o.jwksUri = next(args, ++i, a);
                        keySources++;
                    }
                    case "--issuer" -> {
                        o.issuer = next(args, ++i, a);
                        keySources++;
                    }
                    default -> {
                        if (a.startsWith("--")) {
                            throw new IllegalArgumentException("Unknown option: " + a + "\n\n" + USAGE);
                        }
                        if (o.token != null) {
                            throw new IllegalArgumentException("Only one token can be decoded at a time.");
                        }
                        o.token = a;
                    }
                }
            }
            if (keySources > 1) {
                throw new IllegalArgumentException(
                        "Use only one of --secret, --secret-base64, --public-key, --jwks, --issuer.");
            }
            return o;
        }

        private static String next(String[] args, int i, String option) {
            if (i >= args.length) {
                throw new IllegalArgumentException(option + " needs a value.");
            }
            return args[i];
        }
    }
}
