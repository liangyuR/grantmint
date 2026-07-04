package dev.hg.grantmint.server.signing;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hand-rolled AWS Signature Version 4 (the only piece of AWS auth the {@code awssm:} scheme needs),
 * kept SDK-free so the single-binary/native-image story stays lean. The algorithm is pinned by a
 * unit test against AWS's published signing example — do not "simplify" the canonicalization steps;
 * every byte of the canonical request is part of the signature.
 *
 * <p>See <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html">AWS
 * SigV4 specification</a>.
 */
final class AwsSigV4 {

    private AwsSigV4() {}

    /**
     * Compute the {@code Authorization} header for the request. {@code headers} must already contain
     * {@code x-amz-date} (and any other headers to sign); the {@code host} header is derived from the
     * URI and signed implicitly — the JDK client sends it automatically and refuses to set it by hand.
     */
    static String authorizationHeader(
            String method,
            URI uri,
            Map<String, String> headers,
            byte[] body,
            String region,
            String service,
            String accessKeyId,
            String secretAccessKey,
            String amzDate) {
        String dateStamp = amzDate.substring(0, 8);
        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";

        TreeMap<String, String> canonicalHeaders = new TreeMap<>();
        canonicalHeaders.put("host", uri.getHost());
        headers.forEach((name, value) -> canonicalHeaders.put(name.toLowerCase(Locale.ROOT), value.strip()));
        String signedHeaders = String.join(";", canonicalHeaders.keySet());

        String canonicalRequest = canonicalRequest(method, uri, canonicalHeaders, signedHeaders, body);
        String stringToSign = String.join(
                "\n",
                "AWS4-HMAC-SHA256",
                amzDate,
                credentialScope,
                HexFormat.of().formatHex(sha256(canonicalRequest.getBytes(StandardCharsets.UTF_8))));

        byte[] signingKey = hmac(
                hmac(
                        hmac(hmac(("AWS4" + secretAccessKey).getBytes(StandardCharsets.UTF_8), dateStamp), region),
                        service),
                "aws4_request");
        String signature = HexFormat.of().formatHex(hmac(signingKey, stringToSign));

        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/" + credentialScope + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;
    }

    static String canonicalRequest(
            String method, URI uri, Map<String, String> canonicalHeaders, String signedHeaders, byte[] body) {
        String headerBlock = canonicalHeaders.entrySet().stream()
                .map(e -> e.getKey() + ":" + e.getValue())
                .collect(Collectors.joining("\n"));
        return String.join(
                "\n",
                method,
                uri.getRawPath().isEmpty() ? "/" : uri.getRawPath(),
                canonicalQuery(uri.getRawQuery()),
                headerBlock,
                "",
                signedHeaders,
                HexFormat.of().formatHex(sha256(body == null ? new byte[0] : body)));
    }

    /** RFC 3986-encode and sort the query parameters (key, then value) as SigV4 requires. */
    static String canonicalQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return "";
        }
        // SigV4 sorts by key name (then value), NOT by the joined "key=value" string — the '='
        // would otherwise sort after digits and misorder prefix keys like "key" vs "key2".
        record Param(String key, String value) {}
        List<Param> pairs = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            pairs.add(new Param(rfc3986Encode(urlDecode(key)), rfc3986Encode(urlDecode(value))));
        }
        return pairs.stream()
                .sorted(java.util.Comparator.comparing(Param::key).thenComparing(Param::value))
                .map(p -> p.key() + "=" + p.value())
                .collect(Collectors.joining("&"));
    }

    static String rfc3986Encode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '.'
                    || c == '_'
                    || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append(String.format(Locale.ROOT, "%02X", c));
            }
        }
        return out.toString();
    }

    private static String urlDecode(String value) {
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
