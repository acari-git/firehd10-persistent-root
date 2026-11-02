package io.github.voidnullvalue.snusnuroot.persistence;

import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.AtomicFile;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileLock;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * V2 journal: adds the genesis bootstrap, per-attempt challenges and the
 * boot-count latch on top of the reviewed v1 one-shot semantics.
 * Design: FIREHD10_JOURNAL_BOOTSTRAP_AND_PROOF_CUSTODY_DESIGN_20261101.md
 *
 * Record grammar (strict, no normalization):
 *   READY:<bootId>:<bootCount>
 *   INFLIGHT:<bootId|?>:<bootCount>:<challengeHex64>:<prevBootId>
 * Missing file = EMPTY. Anything else = FOREIGN: every operation denies
 * and the bytes are preserved untouched for forensic inspection.
 *
 * Authorization NEVER comes from an app-side identity claim. READY is
 * created only by transitions backed by an ECDSA proof verified against
 * the pinned signer key (genesis / completion / lockout recovery). The
 * witness boot id and Settings boot_count are anti-replay latches and
 * consistency claims; the signer independently reads the kernel boot id
 * and binds it into every signature it issues.
 *
 * The UID10055 app owns its direct-boot private directory. All journal
 * family files (state, boot guard, genesis challenge) are serialized by
 * one process mutex plus one advisory file lock, as in v1.
 */
public final class Stage4AttemptJournalV2 {
    private static final String FILENAME = "stage4-native-attempt-v2.state";
    private static final String GUARD_FILENAME = "stage4-boot-guard.state";
    private static final String GENESIS_CHALLENGE_FILENAME =
            "stage4-genesis-challenge.state";
    private static final String BOOT =
            "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}";
    private static final String HEX64 = "[0-9a-f]{64}";
    private static final String COUNT = "(0|[1-9][0-9]{0,9})";
    private static final Object PROCESS_LOCK = new Object();

    private static final int KIND_EMPTY = 0;
    private static final int KIND_READY = 1;
    private static final int KIND_INFLIGHT = 2;
    private static final int KIND_FOREIGN = 3;

    private final File parentDirectory;
    private final AtomicFile record;
    private final AtomicFile guard;
    private final AtomicFile genesisChallenge;
    private final File stateFile;
    private final File guardFile;
    private final File genesisChallengeFile;
    private final File lockFile;

    public Stage4AttemptJournalV2(Context appContext) {
        Context directBoot = appContext.createDeviceProtectedStorageContext();
        File dir = directBoot.getFilesDir();
        this.parentDirectory = dir;
        this.stateFile = new File(dir, FILENAME);
        this.guardFile = new File(dir, GUARD_FILENAME);
        this.genesisChallengeFile = new File(dir, GENESIS_CHALLENGE_FILENAME);
        this.record = new AtomicFile(stateFile);
        this.guard = new AtomicFile(guardFile);
        this.genesisChallenge = new AtomicFile(genesisChallengeFile);
        this.lockFile = new File(dir, FILENAME + ".lock");
    }

    private static final class State {
        int kind = KIND_FOREIGN;
        String boot;
        long count = -1;
        String challenge;
        String prevBoot;
    }

    public String stateKind() {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return "UNKNOWN";
                switch (parseState(readRaw(record, stateFile)).kind) {
                    case KIND_EMPTY: return "EMPTY";
                    case KIND_READY: return "READY";
                    case KIND_INFLIGHT: return "INFLIGHT";
                    default: return "FOREIGN";
                }
            } catch (IOException | RuntimeException error) {
                return "UNKNOWN";
            }
        }
    }

    public boolean isInflight() {
        return "INFLIGHT".equals(stateKind());
    }

    /** Boot id bound by the current READY record, or null unless the
     * record is a well-formed READY. Read-only: never writes. */
    public String readyBoot() {
        synchronized (PROCESS_LOCK) {
            State state = parseState(readRaw(record, stateFile));
            return state.kind == KIND_READY ? state.boot : null;
        }
    }

    /** Boot count bound by the current READY record, or -1 unless the
     * record is a well-formed READY. Read-only: never writes. */
    public long readyCount() {
        synchronized (PROCESS_LOCK) {
            State state = parseState(readRaw(record, stateFile));
            return state.kind == KIND_READY ? state.count : -1;
        }
    }

    /**
     * Issue the genesis challenge. Only from EMPTY (first bootstrap)
     * or INFLIGHT (lockout recovery). Idempotent: an existing well-formed
     * challenge is returned unchanged, because the attended session reads
     * it (as root) and hands it to the signer; reissuing in between would
     * invalidate an in-flight signature for no benefit. The challenge is
     * consumed (deleted) by every genesis verification attempt. It is not
     * a secret; its role is freshness and binding. Returns hex or null.
     */
    public String issueGenesisChallenge() {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return null;
                State state = parseState(readRaw(record, stateFile));
                if (state.kind != KIND_EMPTY && state.kind != KIND_INFLIGHT) {
                    return null;
                }
                String existing = readRaw(genesisChallenge,
                        genesisChallengeFile);
                if (existing != null && existing.matches(HEX64)) {
                    return existing;
                }
                String challenge = randomHex64();
                if (!writeAtomic(genesisChallenge, challenge)) return null;
                return challenge.equals(readRaw(genesisChallenge,
                        genesisChallengeFile)) ? challenge : null;
            } catch (IOException | RuntimeException error) {
                return null;
            }
        }
    }

    /** EMPTY -> READY, only with a valid genesis proof (design section 1). */
    public boolean installGenesis(String witnessBootId, long bootCount,
            PublicKey verifierKey, String message, String signatureHex) {
        return genesisTransition(KIND_EMPTY, witnessBootId, bootCount,
                verifierKey, message, signatureHex);
    }

    /** INFLIGHT -> READY: the only way out of a lockout besides completion. */
    public boolean recoverLockoutWithGenesis(String witnessBootId,
            long bootCount, PublicKey verifierKey, String message,
            String signatureHex) {
        return genesisTransition(KIND_INFLIGHT, witnessBootId, bootCount,
                verifierKey, message, signatureHex);
    }

    private boolean genesisTransition(int requiredKind, String witnessBootId,
            long bootCount, PublicKey verifierKey, String message,
            String signatureHex) {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return false;
                return genesisTransitionLocked(requiredKind, witnessBootId,
                        bootCount, verifierKey, message, signatureHex);
            } catch (IOException | RuntimeException error) {
                return false;
            }
        }
    }

    private boolean genesisTransitionLocked(int requiredKind,
            String witnessBootId, long bootCount, PublicKey verifierKey,
            String message, String signatureHex) {
        if (witnessBootId == null || !witnessBootId.matches(BOOT)
                || bootCount < 0 || verifierKey == null || message == null
                || signatureHex == null) {
            return false;
        }
        // Genesis is an attended-session operation: a live boot witness is
        // mandatory (no degraded mode), and a readable kernel boot id, when
        // available, must agree with it.
        String proc = Stage4BootIdentity.readCurrentBootId();
        if (proc != null && !proc.equals(witnessBootId)) return false;
        if (parseState(readRaw(record, stateFile)).kind != requiredKind) {
            return false;
        }
        String challenge = readRaw(genesisChallenge, genesisChallengeFile);
        if (challenge == null || !challenge.matches(HEX64)) return false;
        // Consume the challenge on any verification attempt so a recorded
        // proof cannot be ground against repeated journal calls. The
        // signer additionally signs each (boot, challenge) at most once.
        genesisChallengeFile.delete();
        Stage4GenesisVerifier verifier;
        try {
            verifier = new Stage4GenesisVerifier(verifierKey, witnessBootId,
                    challenge);
        } catch (RuntimeException error) {
            return false;
        }
        if (!verifier.verifyOnce(message, signatureHex)) return false;
        String ready = "READY:" + witnessBootId + ":" + bootCount;
        if (!writeAtomic(record, ready)) return false;
        if (!ready.equals(readRaw(record, stateFile))) return false;
        writeAtomic(guard, Long.toString(bootCount));
        return true;
    }

    /**
     * READY -> INFLIGHT. Returns the per-attempt challenge to hand to the
     * signer via the (forgeable, non-authoritative) request channel, or
     * null on denial. witnessBootId may be null (degraded identity mode);
     * the returned INFLIGHT then binds "?" plus the previous READY boot.
     */
    public String beginOneShot(String witnessBootId, long bootCount) {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return null;
                return beginOneShotLocked(witnessBootId, bootCount);
            } catch (IOException | RuntimeException error) {
                return null;
            }
        }
    }

    private String beginOneShotLocked(String witnessBootId, long bootCount) {
        State state = parseState(readRaw(record, stateFile));
        if (state.kind != KIND_READY || bootCount < 0) return null;
        String proc = Stage4BootIdentity.readCurrentBootId();
        if (proc != null && witnessBootId != null
                && !proc.equals(witnessBootId)) {
            return null; // identity sources contradict each other
        }
        String effectiveBoot = proc != null ? proc : witnessBootId;
        // Boot-count latch: strictly newer than the proven boot AND than
        // any boot in which a begin already succeeded. boot_count alone
        // is never an identity; it is an anti-replay latch (design 3.2).
        if (bootCount <= state.count) return null;
        long guardCount = readGuard(state.count);
        if (bootCount <= guardCount) return null;
        if (effectiveBoot != null && effectiveBoot.equals(state.boot)) {
            return null; // never begin twice in the proven boot itself
        }
        // Advance the guard FIRST: if the state write then fails, the
        // READY survives and only this boot's begin is spent.
        if (!writeAtomic(guard, Long.toString(bootCount))) return null;
        String challenge = randomHex64();
        String inflight = "INFLIGHT:" + (effectiveBoot == null
                ? "?" : effectiveBoot) + ":" + bootCount + ":" + challenge
                + ":" + state.boot;
        if (!writeAtomic(record, inflight)) return null;
        return inflight.equals(readRaw(record, stateFile)) ? challenge : null;
    }

    /**
     * INFLIGHT -> READY with the routine signed success proof. Requires
     * same-boot evidence: the kernel/witness boot id matching the
     * INFLIGHT boot (primary mode) or an unchanged boot_count (degraded
     * mode). witnessBootId may be null only in degraded mode.
     */
    public boolean completeWithSignedProof(String witnessBootId,
            long bootCount, PublicKey verifierKey, String message,
            String signatureHex) {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return false;
                return completeWithSignedProofLocked(witnessBootId, bootCount,
                        verifierKey, message, signatureHex);
            } catch (IOException | RuntimeException error) {
                return false;
            }
        }
    }

    private boolean completeWithSignedProofLocked(String witnessBootId,
            long bootCount, PublicKey verifierKey, String message,
            String signatureHex) {
        State state = parseState(readRaw(record, stateFile));
        if (state.kind != KIND_INFLIGHT || verifierKey == null
                || message == null || signatureHex == null) {
            return false;
        }
        String proc = Stage4BootIdentity.readCurrentBootId();
        if (proc != null && witnessBootId != null
                && !proc.equals(witnessBootId)) {
            return false;
        }
        // Same-boot evidence. A proof presented in a LATER boot must not
        // launder a stale INFLIGHT into a fresh READY (2026-10-15 lesson).
        if (!"?".equals(state.boot)) {
            boolean sameBoot = proc != null
                    ? proc.equals(state.boot)
                    : (witnessBootId != null
                            && witnessBootId.equals(state.boot)
                            && bootCount == state.count);
            if (!sameBoot) return false;
        } else {
            if (bootCount != state.count) return false;
            if (proc != null) {
                // In degraded mode a readable kernel id must at least not
                // be the previous proven boot.
                if (proc.equals(state.prevBoot)) return false;
            }
        }
        String[] fields = message.split("\\|", -1);
        if (fields.length != 6 || !"stage4-root-v1".equals(fields[0])
                || !fields[1].matches(BOOT)
                || !fields[2].equals(state.challenge)
                || !"uid=0".equals(fields[3])
                || !"ctx=u:r:magisk:s0".equals(fields[4])
                || !"selinux=Enforcing".equals(fields[5])) {
            return false;
        }
        String provenBoot = fields[1];
        if (!"?".equals(state.boot)) {
            if (!provenBoot.equals(state.boot)) return false;
        } else if (provenBoot.equals(state.prevBoot)) {
            return false; // degraded mode still needs a NEW proven boot
        }
        if (proc != null && !proc.equals(provenBoot)) return false;
        Stage4ProofVerifier verifier;
        try {
            verifier = new Stage4ProofVerifier(verifierKey, provenBoot,
                    state.challenge);
        } catch (RuntimeException error) {
            return false;
        }
        if (!verifier.verifyOnce(message, signatureHex)) return false;
        String ready = "READY:" + provenBoot + ":" + state.count;
        if (!writeAtomic(record, ready)) return false;
        if (!ready.equals(readRaw(record, stateFile))) return false;
        writeAtomic(guard, Long.toString(state.count));
        return true;
    }

    /** True unless the record is a well-formed READY (v1 semantics). */
    public boolean pendingOrUnknown() {
        synchronized (PROCESS_LOCK) {
            try (RandomAccessFile mutexFile = new RandomAccessFile(lockFile, "rw");
                    FileLock lock = mutexFile.getChannel().tryLock()) {
                if (lock == null) return true;
                return parseState(readRaw(record, stateFile)).kind
                        != KIND_READY;
            } catch (IOException | RuntimeException error) {
                return true;
            }
        }
    }

    private State parseState(String raw) {
        State state = new State();
        if (raw == null) {
            state.kind = KIND_EMPTY;
            return state;
        }
        String[] parts = raw.split(":", -1);
        if (parts.length == 3 && "READY".equals(parts[0])
                && parts[1].matches(BOOT) && parts[2].matches(COUNT)) {
            state.kind = KIND_READY;
            state.boot = parts[1];
            state.count = Long.parseLong(parts[2]);
            return state;
        }
        if (parts.length == 5 && "INFLIGHT".equals(parts[0])
                && ("?".equals(parts[1]) || parts[1].matches(BOOT))
                && parts[2].matches(COUNT) && parts[3].matches(HEX64)
                && parts[4].matches(BOOT)) {
            state.kind = KIND_INFLIGHT;
            state.boot = parts[1];
            state.count = Long.parseLong(parts[2]);
            state.challenge = parts[3];
            state.prevBoot = parts[4];
            return state;
        }
        state.kind = KIND_FOREIGN;
        return state;
    }

    private long readGuard(long fallback) {
        String raw = readRaw(guard, guardFile);
        if (raw == null || !raw.matches(COUNT)) return fallback;
        return Long.parseLong(raw);
    }

    /** Raw record text, or null when the file is absent or unreadable. */
    private String readRaw(AtomicFile file, File base) {
        if (!base.exists()) return null;
        try {
            byte[] bytes = file.readFully();
            if (bytes.length < 1 || bytes.length > 256) return null;
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    private boolean writeAtomic(AtomicFile file, String value) {
        FileOutputStream stream = null;
        try {
            stream = file.startWrite();
            stream.write(value.getBytes(StandardCharsets.UTF_8));
            file.finishWrite(stream);
            stream = null;
            // finishWrite syncs the file; the parent directory must also
            // be synced for the rename to survive a crash (v1 lesson).
            return syncParentDirectory();
        } catch (IOException | RuntimeException error) {
            if (stream != null) {
                try {
                    file.failWrite(stream);
                } catch (RuntimeException ignored) {
                    // Refuse to proceed after a failed rollback.
                }
            }
            return false;
        }
    }

    private boolean syncParentDirectory() {
        FileDescriptor fd = null;
        boolean synced = false;
        try {
            fd = Os.open(parentDirectory.getAbsolutePath(),
                    OsConstants.O_RDONLY | OsConstants.O_NOFOLLOW, 0);
            if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) return false;
            Os.fsync(fd);
            synced = true;
        } catch (ErrnoException | RuntimeException ignored) {
            synced = false;
        } finally {
            if (fd != null) {
                try {
                    Os.close(fd);
                } catch (ErrnoException ignored) {
                    synced = false;
                }
            }
        }
        return synced;
    }

    private static String randomHex64() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        StringBuilder hex = new StringBuilder(64);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >>> 4) & 15, 16));
            hex.append(Character.forDigit(b & 15, 16));
        }
        return hex.toString();
    }
}
