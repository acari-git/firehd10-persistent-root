package io.github.voidnullvalue.snusnuroot.persistence;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * Verifies a genesis proof (design doc section 1.2). Genesis is a HIGHER
 * privilege operation than a routine success proof: it creates the first
 * READY record from EMPTY, or clears an INFLIGHT lockout. It therefore
 * uses a separate message domain (stage4-genesis-v1) so a routine
 * stage4-root-v1 receipt can never be replayed as a genesis, and it binds
 * the exact firmware build so a genesis minted for another build or an
 * OTA-surviving record cannot authorize this one.
 *
 * As with Stage4ProofVerifier, this class only checks a signature against
 * a pinned key. Whether the signer really held MagiskSU uid=0 is the
 * signer's own gating contract (design doc section 2.4), not something a
 * verifier can establish.
 */
public final class Stage4GenesisVerifier {
    static final String BUILD_ID = "PS7331.4463N";
    static final String INCREMENTAL = "0031575863172";
    private static final String BOOT =
            "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}";
    private static final String HEX = "[0-9a-f]{64}";
    private final String expectedMessage;
    private final PublicKey verifierKey;
    private boolean consumed;

    public Stage4GenesisVerifier(PublicKey verifierKey, String bootId,
            String challenge) {
        if (!(verifierKey instanceof ECPublicKey)
                || ((ECPublicKey) verifierKey).getParams().getCurve()
                        .getField().getFieldSize() != 256
                || bootId == null || !bootId.matches(BOOT)
                || challenge == null || !challenge.matches(HEX)) {
            throw new IllegalArgumentException("invalid genesis contract");
        }
        this.verifierKey = verifierKey;
        this.expectedMessage = "stage4-genesis-v1|" + bootId + "|"
                + challenge + "|" + BUILD_ID + "|" + INCREMENTAL
                + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
    }

    /** Returns true only once, for the exact message and a valid signature. */
    public synchronized boolean verifyOnce(String message,
            String signatureHex) {
        if (consumed || !expectedMessage.equals(message)
                || signatureHex == null
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
