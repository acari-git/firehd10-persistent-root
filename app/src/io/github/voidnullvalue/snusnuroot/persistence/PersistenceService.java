package io.github.voidnullvalue.snusnuroot.persistence;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;

import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;

public final class PersistenceService extends Service {
    private static final String TAG = "SnuSnuPersist";
    private static final String ENABLED_KEY = "snusnu_persist_enabled";
    private static final String STATUS_KEY = "snusnu_persist_status";
    private static final String REARM_STATUS_KEY = "snusnu_rearm_status";
    private static final String RETRY_COUNT_KEY = "snusnu_retry_count";
    private static final String NATIVE_RESULT_KEY = "snusnu_native_result";
    private static final String PROOF_STATUS_KEY = "snusnu_proof_status";
    /* V2 proof mailbox (design doc 2.5): the root-side signer drops the
     * signed success proof into the app's own device-protected files dir;
     * the shared cache state dir is the fallback location. */
    private static final String PROOF_DROP_NAME = "stage4-proof.txt";
    private static final String GENESIS_DROP_NAME = "stage4-genesis.txt";
    private static final String PROOF_DROP_DIR = "proof-drop";
    private static final String BOOT_ID_KEY = "snusnu_persist_boot_id";
    private static final String EXEMPTIONS = "hidden_api_blacklist_exemptions";
    /* PS7319 boot fix. Upstream keeps the carrier's scratch output in
     * /data/securedStorageLocation/snusnu/state. That tree is
     * assetstorage_data_file, and this firmware's policy grants system_app -- the
     * UID-1000 domain this service's injected channel runs in -- no search on it,
     * so the channel's rm/create/read all return EACCES and every boot ends in
     * system_native_failed:
     *   avc: denied { search } for name="securedStorageLocation"
     *     scontext=u:r:system_app:s0 tcontext=u:object_r:assetstorage_data_file:s0
     * Measured, not inferred. /data/cache is cache_file, which system_app may
     * search and create/unlink in, so the state lives there instead. It is also
     * created on demand below, because /data/cache is scratch space and is not
     * guaranteed to survive an OTA. */
    private static final String STATE_DIR = "/data/cache/snusnu/state";
    private static final String TRIGGER =
            "x[$(sleep 30;/system/bin/sh /data/securedStorageLocation/w/b)]000";
    /* The re-arm watchdog is installed by root at WATCHDOG_PATH, not generated
     * here. It used to be written into the actor's own 0777 scratch directory and
     * executed from there, which let any local app replace it and run code as
     * uid 1000 -- a direct path back to re-arming root. The script is now
     * root-owned 0755 in a root-owned 0755 directory: the actor can run it but
     * not modify it. Source of truth: stage4-persistent/watchdog.sh.
     *
     * Why a watchdog is needed at all: persist.sys.saved_time is not durable on
     * this firmware. Amazon's TimeService NTP-syncs over it ~20 s and ~130 s into
     * boot, overwriting the armed trigger, so the NEXT boot would have nothing to
     * fire while this actor still reported success. See watchdog.sh. */
    private static final String WATCHDOG_PATH = "/data/snusnu_root/bin/watchdog.sh";
    /* On-demand waiter launcher (trigger design, 2026-11-01), installed
     * root-owned beside the watchdog. Invoked through the channel after
     * the journal is INFLIGHT; see runPersistence. Source of truth:
     * stage4-persistent/snusnu-launch.sh. Design:
     * FIREHD10_WAITER_TRIGGER_ON_DEMAND_LAUNCH_DESIGN_20261101.md. */
    private static final String LAUNCHER_PATH =
            "/data/snusnu_root/bin/snusnu-launch.sh";
    private static final int SYSTEM_CHANNEL_PORT = 4321;
    // The actor keeps its auth token in credential-encrypted device-protected private storage.
    private static final String AUTH_FILENAME = "channel-auth";
    private static final int NOTIFICATION_ID = 31317;
    private static final String NOTIFICATION_CHANNEL = "snusnu_persistence";
    private static volatile boolean running;
    private static volatile boolean rerunRequested;
    private String currentBootId;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager manager = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL,
                "SnuSnuRoot startup", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Restores SnuSnuRoot after device startup");
        manager.createNotificationChannel(channel);
        Notification notification = new Notification.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle("SnuSnuRoot")
                .setContentText("Restoring privileged state")
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        synchronized (PersistenceService.class) {
            if (running) {
                rerunRequested = true;
                return START_NOT_STICKY;
            }
            running = true;
        }
        new Thread(() -> {
            try {
                do {
                    rerunRequested = false;
                    runPersistence();
                    if (rerunRequested) {
                        try {
                            Thread.sleep(2000L);
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                } while (rerunRequested);
            } catch (Throwable unexpected) {
                // Never leave the privileged trigger armed after a Java-side crash.
                Log.e(TAG, "unhandled persistence exception", unexpected);
                report("internal_exception");
            } finally {
                running = false;
                stopSelf();
            }
        }, "snusnu-persist").start();
        return START_NOT_STICKY;
    }

    private void runPersistence() {
        ContentResolver resolver = getContentResolver();
        // V2: proof drops are processed even while the actor is disabled.
        // A verified routine completion re-arms the actor for the NEXT
        // boot (see processProofDrops); genesis drops are operator-session
        // artifacts, never re-arm, and must not depend on the actor
        // being enabled.
        if (processProofDrops(resolver)) {
            // This run was the completion run for an earlier attempt. It
            // must not fall through into a fresh attempt: the journal is
            // READY bound to this very boot, a begin here is latched off,
            // and the denial report would disarm the re-arm.
            Log.i(TAG, "proof completed this run; re-armed for next boot");
            return;
        }
        if (!"1".equals(Settings.Global.getString(resolver, ENABLED_KEY))) {
            Log.i(TAG, "disabled by global setting");
            return;
        }
        if (checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS)
                != PackageManager.PERMISSION_GRANTED) {
            report("missing_write_secure_settings");
            return;
        }
        BootClaims claims = currentBootClaims();
        String bootId = claims.bootId;
        Context deviceContext = createDeviceProtectedStorageContext();
        String previousBoot = deviceContext.getSharedPreferences("state", MODE_PRIVATE)
                .getString("last_boot_id", "");
        if (bootId != null && bootId.equals(previousBoot)) {
            Log.i(TAG, "already attempted this boot");
            return;
        }
        if (bootId != null) {
            currentBootId = bootId;
        }
        // The journal's READY record names the last PROVEN boot. If it
        // names THIS boot, the cycle already completed here and the
        // completion run re-armed the flag; a later start on the same
        // boot (a queued BOOT_COMPLETED rerun, an AMS restart) must be
        // a quiet no-op. Falling through to beginOneShot would be
        // denied by the boot-count latch, and the denial report would
        // disarm the standing posture. The prefs guard above cannot
        // catch this: nothing ever writes last_boot_id.
        Stage4AttemptJournalV2 proven = new Stage4AttemptJournalV2(this);
        if (claims.bootCount >= 0
                && proven.readyCount() == claims.bootCount
                && (bootId == null || bootId.equals(proven.readyBoot()))) {
            Log.i(TAG, "already proven this boot");
            return;
        }
        // Do NOT start the UID1000 system channel or watchdog before the
        // direct-boot app journal is durably INFLIGHT. Missing/corrupt journal
        // denies the operation and turns off persistent auto execution.
        Stage4AttemptJournalV2 oneShot = new Stage4AttemptJournalV2(this);
        String attemptChallenge = oneShot.beginOneShot(bootId, claims.bootCount);
        if (attemptChallenge == null) {
            Settings.Global.putString(resolver, REARM_STATUS_KEY, "journal_denied");
            report("journal_denied");
            return;
        }
        resolver.delete(Settings.Global.getUriFor(NATIVE_RESULT_KEY), null, null);
        Settings.Global.putString(resolver, REARM_STATUS_KEY, "disabled_one_shot");
        report("starting");

        /* Schedule the guard first, independently of exploit success. 4460N
         * normally leaves saved_time armed after time_update exits, but the
         * UID-1000 worker restores it if that vendor behavior ever changes. */
        if (!spawnSystemChannel()) {
            report("rearm_spawn_failed");
            return;
        }
        // Hand the journal-issued challenge to the root-side signer via
        // the channel. The request file is forgeable by UID1000 and that
        // is safe: the journal is the challenge authority and the signer
        // re-derives every fact it signs (design doc 2.5).
        writeProofRequest(bootId, attemptChallenge);
        // A pre-root watchdog would re-arm persist.sys.saved_time before the
        // dangerous native operation completed, defeating the crash lockout.
        // No unattended rearm is performed in this review-only fail-closed
        // version. Do not mistake this for persistent MagiskSU implementation.
        Log.i(TAG, "durable one-shot INFLIGHT; automatic rearm disabled");

        /* Waiter launch (trigger design, 2026-11-01). The waiter can no
         * longer be relied on to self-launch from a trigger string armed
         * during a previous boot: TimeService overwrites
         * persist.sys.saved_time early in boot, and the watchdog poll
         * that used to repair that is retired by the journal authority
         * decision. Instead, the journal -- through this INFLIGHT-gated
         * flow and no other path -- asks the launcher to start the
         * time_update service on demand, in this boot, seconds before
         * the carrier runs. The launcher arms the property only for
         * the moments the stock service needs to read it and restores
         * the captured numeric value before returning; nothing stays
         * armed across a reboot.
         *
         * If the waiter cannot be confirmed launched, the carrier must
         * NOT run: flipping SELinux Permissive with no waiter waiting
         * would leave this boot with no restore and no Enforcing
         * return. The INFLIGHT lockout that follows is the same
         * fail-closed residual the architecture already accepts for a
         * carrier that runs and fails. */
        String launchOutput = sendSystemCommand(
                "/system/bin/sh " + LAUNCHER_PATH + " launch");
        if (launchOutput == null || !launchOutput.contains("LAUNCH_RESULT OK")) {
            Settings.Global.putString(resolver, REARM_STATUS_KEY,
                    "waiter_launch_failed");
            report("waiter_launch_failed");
            return;
        }
        Log.i(TAG, "waiter launch confirmed by launcher");

        String nativeResult = sendSystemCommand(
                "for i in $(seq 1 120); do "
                + "[ \"$(getprop sys.boot_completed)\" = 1 ] && break; sleep 1; done; "
                + "sleep 5; mkdir -p " + STATE_DIR + " 2>/dev/null; "
                + "out=" + STATE_DIR + "/native_result; "
                + "pidfile=" + STATE_DIR + "/carrier_pid; "
                /* Build and digest gate, before anything touches the kernel.
                 *
                 * The carrier is an OTA-updatable system: an update can change
                 * the kernel while /data keeps the old carrier, and the actor
                 * would launch it on the next boot against a kernel whose
                 * selinux_enforcing address it no longer matches. Nothing about
                 * the install-time permission/label checks would catch that.
                 *
                 * The guard file is written by the installer and records what
                 * was actually verified on this device. Missing guard file =
                 * refuse, because "the check could not run" must not be treated
                 * as "the check passed". */
                + "guard=/data/cache/snusnu/expected-build; "
                + "if [ ! -f \"$guard\" ]; then echo __SNU_GUARD_MISSING__; exit; fi; "
                + "want_ps=$(sed -n 's/^ps=//p' \"$guard\" | head -1); "
                + "want_inc=$(sed -n 's/^incremental=//p' \"$guard\" | head -1); "
                + "want_sha=$(sed -n 's/^carrier_sha=//p' \"$guard\" | head -1); "
                /* The guard must not be optional: cache truncation previously
                 * skipped the comparison and ran a stale kernel carrier after
                 * an OTA. Check every field against this exact-device build
                 * BEFORE reading or executing the carrier. */
                + "if [ \"$want_ps\" != PS7331.4463N ] "
                + "|| [ \"$want_inc\" != 0031575863172 ] "
                + "|| [ \"$want_sha\" != 604725775c9a9121b7c36fd63c077d0f8fab5511101dae78ef4f5265c2f25841 ]; "
                + "then echo __SNU_GUARD_INVALID__; exit; fi; "
                + "got_ps=$(getprop ro.build.id); "
                + "got_inc=$(getprop ro.build.version.incremental); "
                + "if [ \"$got_ps\" != \"$want_ps\" ] || [ \"$got_inc\" != \"$want_inc\" ]; then "
                + "echo __SNU_BUILD_MISMATCH__; exit; fi; "
                + "got_sha=$(toybox sha256sum /data/snusnu_hwbinder_root 2>/dev/null | cut -d' ' -f1); "
                + "if [ \"$got_sha\" != \"$want_sha\" ]; then "
                + "echo __SNU_CARRIER_MISMATCH__; exit; fi; "
                /* Retry in-boot. Measured on this device: a boot whose first
                 * carrier attempt returned ENODATA
                 * (HWBINDER_STATEFUL result=0x5000003d00000000) succeeded on the
                 * very next attempt, leaving SELinux Permissive. Stage 1 asserted
                 * the opposite -- "in-boot carrier respawn cannot clear
                 * ENODATA/EALREADY" -- which is why the actor fires once and a miss
                 * cost a whole reboot. That assertion does not hold here, so the
                 * miss MAY be recoverable. On PS7331.4463N require explicit
                 * ENODATA with no write and cap this process to one attempt;
                 * never infer success from the carrier marker alone.
                 *
                 * Progress is echoed per attempt on purpose: this command runs over
                 * a socket whose read timeout is 120 s, and a silent stretch longer
                 * than that would be read as a failure even when the carrier later
                 * succeeds. The lease is 30 s per attempt; the carrier answers in
                 * ~4-11 s once the 10 ms rescale is applied. */
                + "for attempt in 1; do "
                + "[ \"$(settings get global snusnu_persist_enabled)\" = 1 ] || { echo __SNU_DISABLED_DURING_RETRY__; exit; }; "
                + "echo \"__SNU_CARRIER_ATTEMPT_${attempt}__\"; "
                + "rm -f \"$out\"; /data/snusnu_hwbinder_root stateful-root-hold "
                + "</dev/null >\"$out\" 2>&1 & keeper=$!; "
                + "printf '%s\\n' \"$keeper\" >\"$pidfile\"; "
                + "n=0; "
                + "while [ $n -lt 30 ]; do "
                + "if grep -q __SNU_NATIVE_0__ \"$out\" 2>/dev/null; then break; fi; "
                + "if ! kill -0 \"$keeper\" 2>/dev/null; then break; fi; "
                + "sleep 1; n=$((n + 1)); done; "
                + "if grep -q __SNU_NATIVE_0__ \"$out\" 2>/dev/null; then "
                + "cat \"$out\"; if [ \"$(getenforce 2>&1)\" = Permissive ]; then "
                + "echo __SNU_VERIFIED_PERMISSIVE__; else echo __SNU_WRITE_NOT_EFFECTIVE__; fi; exit; fi; "
                + "kill \"$keeper\" 2>/dev/null || true; wait \"$keeper\" 2>/dev/null || true; "
                + "if grep -q \"HWBINDER_STATEFUL result=0x5000003d00000000\" \"$out\" 2>/dev/null "
                + "&& ! grep -q \"HWBINDER_STATEFUL_WRITE\" \"$out\" 2>/dev/null; then "
                + "echo \"__SNU_ENODATA_MISS_${attempt}__\"; "
                + "else cat \"$out\"; echo __SNU_UNEXPECTED_NATIVE_FAILURE__; exit; fi; "
                + "sleep 12; done; "
                + "echo __SNU_ENODATA_EXHAUSTED__; exit");
        if (nativeResult == null) {
            // Command could have run before the socket failed. Stop the
            // actor, preserve INFLIGHT, and refuse a second kernel attempt.
            report("native_result_unknown_no_retry");
            return;
        }
        // Keep status codes/attempt markers but never place kernel pointer
        // fields from the native carrier into logcat or Settings.Global.
        String safeNativeResult = NativeOutputSanitizer.redact(nativeResult);
        Log.i(TAG, "system native result=" + safeNativeResult);
        Settings.Global.putString(getContentResolver(), NATIVE_RESULT_KEY,
                safeNativeResult.trim().replace('\n', ';'));
        /* The gate markers mean the carrier was deliberately NOT run, which is a
         * different condition from a carrier that ran and lost its race. Report
         * them distinctly so an OTA that invalidates the install is obvious
         * rather than looking like a flaky race. */
        if (nativeResult != null) {
            if (nativeResult.contains("__SNU_BUILD_MISMATCH__")) {
                report("build_mismatch");
                return;
            }
            if (nativeResult.contains("__SNU_CARRIER_MISMATCH__")) {
                report("carrier_mismatch");
                return;
            }
            if (nativeResult.contains("__SNU_GUARD_MISSING__")) {
                report("guard_missing");
                return;
            }
            if (nativeResult.contains("__SNU_GUARD_INVALID__")) {
                report("guard_invalid");
                return;
            }
        }
        if (nativeResult != null && nativeResult.contains("__SNU_WRITE_NOT_EFFECTIVE__")) {
            report("write_unverified");
            return;
        }
        if (nativeResult != null && nativeResult.contains("__SNU_UNEXPECTED_NATIVE_FAILURE__")) {
            report("unexpected_native_failure");
            return;
        }
        if (nativeResult != null && nativeResult.contains("__SNU_DISABLED_DURING_RETRY__")) {
            report("disabled_during_retry");
            return;
        }
        if (nativeResult != null && nativeResult.contains("__SNU_ENODATA_EXHAUSTED__")) {
            report("enodata_exhausted");
            return;
        }
        if (nativeResult == null || !nativeResult.contains("__SNU_NATIVE_0__")
                || !nativeResult.contains("__SNU_VERIFIED_PERMISSIVE__")) {
            report("system_native_failed");
            return;
        }
        report("kernel_write_ok");
    }

    private boolean spawnSystemChannel() {
        String payload = "LClass1;->method1(\n"
                + "10\n"
                + "--runtime-args\n"
                + "--setuid=1000\n"
                + "--setgid=1000\n"
                + "--runtime-flags=2049\n"
                + "--mount-external-full\n"
                + "--setgroups=3003\n"
                + "--nice-name=snusnu-persist-system\n"
                + "--seinfo=platform:targetSdkVersion=28:complete\n"
                + "--invoke-with\n"
                + "toybox nc -s 127.0.0.1 -p 4321 -L /system/bin/sh /data/snusnu_root/bin/system-channel-gate.sh;\n";
        boolean wrote = false;
        try {
            wrote = Settings.Global.putString(getContentResolver(), EXEMPTIONS, payload);
            /* The proven shell path has a process boundary between put/delete.
             * Give zygote's observer the same small delivery window while the
             * foreground service remains alive, then unconditionally clean. */
            Thread.sleep(150L);
        } catch (Throwable error) {
            Log.e(TAG, "zygote injection failed", error);
        } finally {
            try {
                getContentResolver().delete(Settings.Global.getUriFor(EXEMPTIONS),
                        null, null);
            } catch (Throwable error) {
                Log.e(TAG, "CRITICAL: exemptions cleanup failed", error);
            }
        }
        String leftover = Settings.Global.getString(getContentResolver(), EXEMPTIONS);
        if (leftover != null) {
            Log.e(TAG, "CRITICAL: exemptions value remains set; aborting");
            return false;
        }
        return wrote;
    }

    private String sendSystemCommand(String command) {
        // A token embedded in the APK is public. Read instead from app-private
        // device-protected storage, provisioned at install alongside a UID1000-only
        // copy. The gate denies all other localhost clients.
        String token = firstLine(createDeviceProtectedStorageContext().getFilesDir()
                .getAbsolutePath() + "/" + AUTH_FILENAME);
        if (token == null || !token.matches("[0-9a-f]{64}")) {
            Log.e(TAG, "system channel authentication not provisioned");
            return null;
        }
        // Only connection failures BEFORE command submission are retryable.
        boolean nonIdempotentCommandMayHaveBeenSubmitted = false;
        for (int attempt = 0; attempt < 20; ++attempt) {
            try (Socket socket = new Socket(InetAddress.getByName("127.0.0.1"),
                    SYSTEM_CHANNEL_PORT)) {
                socket.setSoTimeout(120000);
                PrintWriter writer = new PrintWriter(
                        new OutputStreamWriter(socket.getOutputStream()), true);
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                writer.println(token);
                // Set the flag BEFORE sending: an uncertain/partial send
                // must never cause a second native kernel operation.
                nonIdempotentCommandMayHaveBeenSubmitted = true;
                writer.println(command);
                writer.flush();
                /* The gate execs an interactive shell on this socket:
                 * it runs the command, then waits for more input, so
                 * without a half-close the reply stream never reaches
                 * EOF and the read below blocks until the socket
                 * timeout even though the command already executed
                 * (measured on boot 195: both commands' effects were
                 * on the device while their replies never terminated).
                 * Half-closing our write side gives the shell EOF
                 * right after the queued command; it exits and the
                 * full reply streams back before the close. */
                socket.shutdownOutput();
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append('\n');
                }
                return output.toString();
            } catch (Throwable error) {
                if (nonIdempotentCommandMayHaveBeenSubmitted) {
                    Log.e(TAG, "unknown privileged command result: never resubmit", error);
                    return null;
                }
                try {
                    Thread.sleep(500L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        return null;
    }

    /** App-side boot identity claims (design doc 3.2): a readable kernel
     * id wins, then a fresh waiter witness, else null (degraded mode).
     * bootCount is an anti-replay latch, never an identity. */
    private static final class BootClaims {
        final String bootId;
        final long bootCount;

        BootClaims(String bootId, long bootCount) {
            this.bootId = bootId;
            this.bootCount = bootCount;
        }
    }

    private BootClaims currentBootClaims() {
        String procBootId = Stage4BootIdentity.readCurrentBootId();
        Stage4BootWitness.Witness witness = Stage4BootWitness.readWitness();
        String witnessBootId = witness != null && Stage4BootWitness.isFresh(
                witness, SystemClock.elapsedRealtime())
                ? witness.bootId : null;
        long bootCount = -1;
        try {
            String raw = Settings.Global.getString(getContentResolver(),
                    Settings.Global.BOOT_COUNT);
            if (raw != null) bootCount = Long.parseLong(raw.trim());
        } catch (Throwable error) {
            Log.e(TAG, "boot_count unreadable; journal will deny", error);
        }
        return new BootClaims(
                Stage4BootWitness.resolveBootId(procBootId, witnessBootId),
                bootCount);
    }

    private void writeProofRequest(String bootId, String challenge) {
        String boot = bootId == null ? "?" : bootId;
        if (!boot.equals("?") && !boot.matches(
                "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                || challenge == null
                || !challenge.matches("[0-9a-f]{64}")) {
            Log.e(TAG, "proof request claims malformed; not written");
            return;
        }
        // Values are journal-internal (UUID / hex / "?"), never user input.
        sendSystemCommand("printf '%s %s\\n' '" + boot + "' '" + challenge
                + "' > " + STATE_DIR + "/proof_request 2>/dev/null; true");
    }

    /**
     * Consume signer drops, in trust order: (1) routine completion of an
     * INFLIGHT attempt, (2) genesis from EMPTY, (3) genesis recovery of a
     * lockout. Rejected drops are left in place as evidence; boot and
     * challenge binding makes them inert.
     *
     * Enabled-flag semantics (enablement closure, 2026-11-02): genesis
     * installs and lockout recoveries never touch the flag -- they are
     * operator-session artifacts, and recording one is not an
     * authorization to attempt again. A ROUTINE completion is different:
     * completeWithSignedProof accepts only a signature, by the device
     * signer over this attempt's journal-issued challenge, attesting a
     * uid=0 / magisk-domain / Enforcing success on this very boot --
     * exactly the "future authenticated Magisk success proof" that
     * report()'s one-shot rule makes the condition for staying enabled.
     * A verified routine completion therefore re-arms the flag for the
     * next boot, and this method returns true so the caller ends the
     * run instead of attempting again on the completion boot. Attempts
     * themselves stay one-shot: report() still disarms on every
     * terminal attempt status, success included, and any failed boot
     * leaves the actor disarmed until an operator re-arms it.
     *
     * @return true iff this call completed an INFLIGHT attempt with a
     *         verified signed proof (and re-armed the actor).
     */
    private boolean processProofDrops(ContentResolver resolver) {
        try {
            Stage4AttemptJournalV2 journal = new Stage4AttemptJournalV2(this);
            String kind = journal.stateKind();
            BootClaims claims = currentBootClaims();
            File dpsDropDir = new File(
                    createDeviceProtectedStorageContext().getFilesDir(),
                    PROOF_DROP_DIR);
            if ("INFLIGHT".equals(kind)) {
                Stage4ProofDrop.Drop drop = Stage4ProofDrop.readDrop(
                        new File(dpsDropDir, PROOF_DROP_NAME));
                String source = "dps";
                if (drop == null) {
                    drop = Stage4ProofDrop.readDrop(
                            new File(STATE_DIR, PROOF_DROP_NAME));
                    source = "cache";
                }
                if (drop != null) {
                    boolean done = journal.completeWithSignedProof(
                            claims.bootId, claims.bootCount,
                            Stage4PinnedProofKey.publicKey(), drop.message,
                            drop.signatureHex);
                    Settings.Global.putString(resolver, PROOF_STATUS_KEY,
                            done ? "proof_completed_" + source
                                    : "proof_rejected");
                    if (done) {
                        // The verified proof is the authenticated success
                        // attestation the one-shot rule requires: re-arm
                        // the actor for the next boot.
                        Settings.Global.putString(resolver, ENABLED_KEY, "1");
                        Settings.Global.putString(resolver, REARM_STATUS_KEY,
                                "rearmed_on_proof");
                        return true;
                    }
                }
            }
            if ("EMPTY".equals(kind) || "INFLIGHT".equals(kind)) {
                Stage4ProofDrop.Drop genesis = Stage4ProofDrop.readDrop(
                        new File(dpsDropDir, GENESIS_DROP_NAME));
                if (genesis != null && claims.bootId != null) {
                    /* A genesis drop is a bootstrap / lockout-recovery
                     * candidate ONLY while it is bound to the journal's
                     * standing genesis challenge: a genuine drop is
                     * always signed over that challenge. The drop a
                     * successful genesis consumed stays in the mailbox
                     * as evidence, but its challenge is spent; without
                     * this gate every later INFLIGHT start would
                     * re-evaluate it, inevitably fail, overwrite the
                     * proof status with a misleading genesis_rejected,
                     * and consume the standing challenge. A non-matching
                     * drop is inert: skip it without touching the proof
                     * status or the challenge. */
                    String standing = journal.issueGenesisChallenge();
                    if (standing != null && standing.equals(
                            genesisChallengeOf(genesis.message))) {
                        boolean done = "EMPTY".equals(kind)
                                ? journal.installGenesis(claims.bootId,
                                        claims.bootCount,
                                        Stage4PinnedProofKey.publicKey(),
                                        genesis.message, genesis.signatureHex)
                                : journal.recoverLockoutWithGenesis(
                                        claims.bootId, claims.bootCount,
                                        Stage4PinnedProofKey.publicKey(),
                                        genesis.message, genesis.signatureHex);
                        Settings.Global.putString(resolver, PROOF_STATUS_KEY,
                                done ? "genesis_installed"
                                        : "genesis_rejected");
                    } else {
                        Log.i(TAG, "genesis drop not bound to standing"
                                + " challenge; ignored");
                    }
                }
            }
        } catch (Throwable error) {
            // A pinned-key or storage failure must never crash the actor
            // into an unsafe state; the journal simply stays unproven.
            Log.e(TAG, "proof drop processing failed closed", error);
        }
        // Keep a genesis challenge available while the journal could
        // accept one, so an attended session can pick it up (as root)
        // and hand it to the signer. Issuance alone authorizes nothing.
        try {
            Stage4AttemptJournalV2 journal = new Stage4AttemptJournalV2(this);
            String kind = journal.stateKind();
            if ("EMPTY".equals(kind) || "INFLIGHT".equals(kind)) {
                journal.issueGenesisChallenge();
            }
        } catch (Throwable error) {
            Log.e(TAG, "genesis challenge issuance failed closed", error);
        }
        return false;
    }

    /** Challenge bound inside a genesis proof message
     * (stage4-genesis-v1|<bootId>|<challengeHex64>|...), or null when
     * the message does not carry a well-formed one. */
    static String genesisChallengeOf(String message) {
        if (message == null) return null;
        String[] fields = message.split("\\|", -1);
        if (fields.length < 3 || !"stage4-genesis-v1".equals(fields[0])
                || !fields[2].matches("[0-9a-f]{64}")) {
            return null;
        }
        return fields[2];
    }

    private void report(String status) {
        Log.i(TAG, "result=" + status);
        try {
            /* Any non-success terminal state is fail-closed across BOOTS, not
             * just across in-boot retries. The watchdog observes this setting
             * on every tick and stops re-arming the privileged trigger. */
            // Even root success is a ONE-SHOT result: never leave the actor
            // enabled without a future authenticated Magisk success proof.
            if (!"starting".equals(status)) {
                Settings.Global.putString(getContentResolver(), ENABLED_KEY, "0");
                Log.w(TAG, "disabled persistence after terminal failure: " + status);
            }
            Settings.Global.putString(getContentResolver(), STATUS_KEY, status);
            if (currentBootId != null) {
                Settings.Global.putString(getContentResolver(), BOOT_ID_KEY, currentBootId);
            }
        } catch (Throwable error) {
            Log.e(TAG, "status/disable write failed", error);
        }
    }

    private static String firstLine(String path) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            return reader.readLine();
        } catch (Throwable error) {
            Log.e(TAG, "cannot read " + path, error);
            return null;
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
