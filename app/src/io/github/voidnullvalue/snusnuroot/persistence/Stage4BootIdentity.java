package io.github.voidnullvalue.snusnuroot.persistence;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * REVIEW ONLY. Read the present kernel boot identity, not a caller's claim.
 * No shell, ADB, SELinux change or root helper is invoked by this class.
 *
 * IMPORTANT DEVICE BLOCKER: the PS7331.4463N stock precompiled SELinux
 * policy denies system_app open/read of proc_random, and the actual boot_id
 * file is labelled proc_random. Shell UID2000 can read it, but that is NOT
 * proof that the UID10055 app can read it. On stock policy this verifier
 * correctly returns null and Stage4AttemptJournal fails closed; it is NOT
 * yet a usable direct-boot identity source in the target app. Do not deploy
 * or assume that a Magisk rule installed after root solves pre-root access.
 */
final class Stage4BootIdentity {
    private static final String PATH = "/proc/sys/kernel/random/boot_id";
    private Stage4BootIdentity() {}

    static String readCurrentBootId() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(PATH), StandardCharsets.US_ASCII))) {
            return parseStrictBootId(in);
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    /** Package-private and pure for host review of malformed proc content. */
    static String parseStrictBootId(BufferedReader in) throws IOException {
        String boot = in.readLine();
        if (boot == null || !boot.matches(
                "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")) {
            return null;
        }
        // readLine removes exactly one line ending; reject additional lines
        // and refuse to normalize caller or source content.
        if (in.readLine() != null) return null;
        return boot;
    }
}
