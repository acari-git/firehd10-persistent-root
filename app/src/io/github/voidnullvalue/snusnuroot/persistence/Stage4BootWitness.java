package io.github.voidnullvalue.snusnuroot.persistence;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * Boot-identity witness (design doc section 3). Under the stock SELinux
 * policy no app domain may read /proc/sys/kernel/random/boot_id, so the
 * uid0 waiter copies the kernel boot id into a small witness file before
 * the app gates. The witness is a CLAIM, never an authorization:
 * forgery or staleness can only cause fail-closed denial, because every
 * READY transition additionally requires an ECDSA proof whose boot id
 * the signer read from /proc itself.
 *
 * File format (strict): line 1 = boot UUID, line 2 = /proc/uptime
 * seconds at write time (freshness sanity only).
 */
public final class Stage4BootWitness {
    public static final String WITNESS_PATH =
            "/data/cache/snusnu/state/boot_witness";
    private static final String BOOT =
            "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}";

    private Stage4BootWitness() {}

    public static final class Witness {
        public final String bootId;
        /** Uptime seconds when written, or -1 when absent/unparseable. */
        public final double uptimeSeconds;

        Witness(String bootId, double uptimeSeconds) {
            this.bootId = bootId;
            this.uptimeSeconds = uptimeSeconds;
        }
    }

    /** Pure parser for host review. Extra lines reject the witness. */
    public static Witness parseLines(String line1, String line2, boolean extraLine) {
        if (line1 == null || !line1.matches(BOOT) || extraLine) return null;
        double uptime = -1;
        if (line2 != null) {
            try {
                uptime = Double.parseDouble(line2.trim());
                if (uptime < 0 || Double.isNaN(uptime)
                        || Double.isInfinite(uptime)) {
                    uptime = -1;
                }
            } catch (NumberFormatException error) {
                uptime = -1;
            }
        }
        return new Witness(line1, uptime);
    }

    public static Witness readWitness() {
        return readWitnessFile(new File(WITNESS_PATH));
    }

    static Witness readWitnessFile(File file) {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            String line1 = in.readLine();
            String line2 = in.readLine();
            boolean extra = in.readLine() != null;
            return parseLines(line1, line2, extra);
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    /**
     * Freshness sanity: uptime resets at every boot, so a witness whose
     * recorded uptime is greater than the current elapsed realtime (plus
     * a small tolerance) cannot have been written during this boot.
     * A smaller value is ambiguous (this boot, or an early write in an
     * earlier boot); the journal's signature anchor and boot-count
     * latch absorb that ambiguity. Witnesses without an uptime are
     * treated as NOT fresh (degraded mode), never as trusted.
     */
    public static boolean isFresh(Witness witness,
            long elapsedRealtimeMillis) {
        if (witness == null || witness.uptimeSeconds < 0) return false;
        return witness.uptimeSeconds * 1000.0
                <= (double) elapsedRealtimeMillis + 5000.0;
    }

    /**
     * Effective boot id claim: a readable kernel id (opportunistic
     * strict source) wins over the witness; otherwise the witness;
     * otherwise null (degraded identity mode).
     */
    public static String resolveBootId(String procBootId,
            String witnessBootId) {
        return procBootId != null ? procBootId : witnessBootId;
    }
}
