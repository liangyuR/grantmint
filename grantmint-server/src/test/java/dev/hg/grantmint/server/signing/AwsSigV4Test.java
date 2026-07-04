package dev.hg.grantmint.server.signing;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Pins the SigV4 implementation to AWS's published signing example (GET iam ListUsers, credential
 * scope 20150830/us-east-1/iam). If any canonicalization detail drifts, these constants — taken
 * from the official docs and independently recomputed — catch it.
 */
class AwsSigV4Test {

    private static final URI VECTOR_URI = URI.create("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08");
    private static final String AMZ_DATE = "20150830T123600Z";

    @Test
    void canonicalRequestMatchesAwsDocumentedExample() throws Exception {
        TreeMap<String, String> canonicalHeaders = new TreeMap<>(Map.of(
                "content-type", "application/x-www-form-urlencoded; charset=utf-8",
                "host", "iam.amazonaws.com",
                "x-amz-date", AMZ_DATE));
        String canonicalRequest = AwsSigV4.canonicalRequest(
                "GET", VECTOR_URI, canonicalHeaders, "content-type;host;x-amz-date", new byte[0]);
        String hash = HexFormat.of()
                .formatHex(
                        MessageDigest.getInstance("SHA-256").digest(canonicalRequest.getBytes(StandardCharsets.UTF_8)));
        assertThat(hash).isEqualTo("f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
    }

    @Test
    void signatureMatchesAwsDocumentedExample() {
        String authorization = AwsSigV4.authorizationHeader(
                "GET",
                VECTOR_URI,
                Map.of("content-type", "application/x-www-form-urlencoded; charset=utf-8", "x-amz-date", AMZ_DATE),
                new byte[0],
                "us-east-1",
                "iam",
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", // gitleaks:allow — AWS's public doc example
                AMZ_DATE);
        assertThat(authorization)
                .isEqualTo("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,"
                        + " SignedHeaders=content-type;host;x-amz-date,"
                        + " Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
    }

    @Test
    void canonicalQuerySortsAndEncodes() {
        assertThat(AwsSigV4.canonicalQuery("b=2&a=1")).isEqualTo("a=1&b=2");
        // sort is by key name, not by the joined pair — '=' must not out-sort '2'
        assertThat(AwsSigV4.canonicalQuery("key2=x&key=y")).isEqualTo("key=y&key2=x");
        assertThat(AwsSigV4.canonicalQuery("key=a b&key2=c/d")).isEqualTo("key=a%20b&key2=c%2Fd");
        assertThat(AwsSigV4.canonicalQuery(null)).isEmpty();
    }
}
