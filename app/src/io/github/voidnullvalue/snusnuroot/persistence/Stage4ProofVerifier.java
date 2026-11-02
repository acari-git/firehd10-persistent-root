package io.github.voidnullvalue.snusnuroot.persistence;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * HOST REVIEW ONLY. Checks a single root-success receipt from a separate actor.
 *
 * The protocol does NOT itself establish that a signer really holds MagiskSU
 * uid=0 or that its SIGNING PRIVATE KEY cannot be read by UID1000; both remain
 * deployment blockers. The app needs only the verifier's PUBLIC KEY. This
 * class neither changes Stage4AttemptJournal nor enables the
 * next-boot trigger. It can only reject mismatched or forged-looking receipts
 * given an assumed trusted signing key and a boot-bound random challenge.
 */
public final class Stage4ProofVerifier {
    private static final String BOOT =
            "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}";
    private static final String HEX = "[0-9a-f]{64}";
    private final String expectedMessage;
    private final String expectedBootId;
    private final PublicKey verifierKey;
    private boolean consumed;

    public Stage4ProofVerifier(PublicKey verifierKey, String bootId, String challenge) {
        if (!(verifierKey instanceof ECPublicKey)
                || ((ECPublicKey) verifierKey).getParams().getCurve().getField().getFieldSize() != 256
                || bootId == null
                || !bootId.matches(BOOT) || challenge == null
                || !challenge.matches(HEX)) {
            throw new IllegalArgumentException("invalid proof verification contract");
        }
        this.verifierKey = verifierKey;
        this.expectedBootId = bootId;
        this.expectedMessage = "stage4-root-v1|" + bootId + "|" + challenge
                + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
    }

    /** Prevent a valid receipt from boot A from authorizing journal boot B. */
    public synchronized boolean verifyOnceForBoot(String journalBootId,
            String message, String signatureHex) {
        return expectedBootId.equals(journalBootId)
                && verifyOnce(message, signatureHex);
    }

    /** Returns true only once for the exact receipt and a valid ECDSA signature. */
    public synchronized boolean verifyOnce(String message, String signatureHex) {
        if (consumed || !expectedMessage.equals(message) || signatureHex == null
                || (signatureHex.length() & 1) != 0
                || !signatureHex.matches("[0-9a-f]{120,160}")) {
            return false;
        }
        byte[] supplied = decodeHex(signatureHex);
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(verifierKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            boolean verified = signature.verify(supplied);
            if (verified) consumed = true;
            return verified;
        } catch (GeneralSecurityException error) {
            return false;
        }
    }

    private static byte[] decodeHex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int a = Character.digit(value.charAt(2 * i), 16);
            int b = Character.digit(value.charAt(2 * i + 1), 16);
            bytes[i] = (byte) ((a << 4) | b);
        }
        return bytes;
    }
}
