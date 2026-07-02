package dev.hg.grantmint.cli;

import java.net.http.HttpResponse;

/** Shared helpers for the CLI's HTTP-backed commands ({@code issue}, {@code revoke}). */
final class CliHttp {

    private CliHttp() {}

    /** Drop a trailing slash from a {@code --server} base URL before appending a path. */
    static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /** Print a non-2xx server response to stderr, preferring the {@code {error, message}} envelope. */
    static void printServerError(HttpResponse<String> response) {
        Object json = JsonBody.parseOrNull(response.body());
        String error = JsonBody.stringField(json, "error");
        String message = JsonBody.stringField(json, "message");
        if (error != null || message != null) {
            System.err.println("error: server rejected the request (HTTP " + response.statusCode() + "): "
                    + (error == null ? "" : error + ": ") + (message == null ? "" : message));
        } else {
            System.err.println(
                    "error: server rejected the request (HTTP " + response.statusCode() + "): " + response.body());
        }
    }
}
