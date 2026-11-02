package io.github.voidnullvalue.snusnuroot.persistence;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Strict parser for a proof mailbox drop (design doc section 2.5).
 * Format: exactly two lines - the canonical proof message and the hex
 * ECDSA signature - with an optional single trailing newline. Anything
 * else (extra lines, CR characters, oversize, non-ASCII) is rejected;
 * the cryptographic check happens in the journal/verifier, this class
 * only enforces the wire shape so malformed drops are cheap to refuse.
 */
public final class Stage4ProofDrop {
    private static final int MAX_DROP_BYTES = 1024;
    private static final int MAX_MESSAGE_CHARS = 220;

    private Stage4ProofDrop() {}

    public static final class Drop {
        public final String message;
        public final String signatureHex;

        Drop(String message, String signatureHex) {
            this.message = message;
            this.signatureHex = signatureHex;
        }
    }

    public static Drop parse(byte[] bytes) {
        if (bytes == null || bytes.length < 32
                || bytes.length > MAX_DROP_BYTES) {
            return null;
        }
        for (byte b : bytes) {
            if ((b & 0xFF) >= 0x7F) return null; // strict ASCII only
        }
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (text.indexOf('\r') >= 0) return null;
        String body = text.endsWith("\n")
                ? text.substring(0, text.length() - 1) : text;
        String[] lines = body.split("\n", -1);
        if (lines.length != 2) return null;
        String message = lines[0];
        String signatureHex = lines[1];
        if (message.length() < 16 || message.length() > MAX_MESSAGE_CHARS) {
            return null;
        }
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            if (c < 0x21 || c > 0x7E) return null;
        }
        if ((signatureHex.length() & 1) != 0
                || !signatureHex.matches("[0-9a-f]{120,160}")) {
            return null;
        }
        return new Drop(message, signatureHex);
    }

    /** Reads a drop file; null on absence, oversize, or any parse error. */
    public static Drop readDrop(File file) {
        try {
            if (file == null || !file.isFile()
                    || file.length() > MAX_DROP_BYTES) {
                return null;
            }
            return parse(Files.readAllBytes(file.toPath()));
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }
}
