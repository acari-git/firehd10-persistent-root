import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * PRODUCTION DEVICE PROOF SIGNER for the Fire HD 10 (KFTRWI / PS7331.4463N)
 * journal-gated persistence design. This is the real signer specified in
 * FIREHD10_JOURNAL_BOOTSTRAP_AND_PROOF_CUSTODY_DESIGN_20261101.md section 2;
 * it is a distinct artifact from v2/host-reference/HostReferenceSigner.java,
 * which is a test-only stand-in with no custody and no gating and must never
 * reach a device.
 *
 * Execution form: a single dependency-free Java class, compiled to a dex and
 * run on-device via app_process from the root (magisk) shell after the
 * October restore flow has established MagiskSU. The launcher is
 * snusnu-proof-signer.sh. The same source compiles and runs on a host JVM,
 * which is how the host cross-tests exercise the production code path; every
 * environment fact source is a file or an absolute-path executable whose
 * location can be overridden with -Dsnu.signer.* properties (host tests
 * stub them at that boundary; production uses the defaults below).
 *
 * Gating contract (design section 2.4): the signer trusts NO caller claim.
 * Before signing it measures, itself, on every invocation:
 *   1. its own uid == 0 and SELinux context == u:r:magisk:s0
 *      (/proc/self/status, /proc/self/attr/current);
 *   2. an independent MagiskSU measurement: <su> -c id run with a hard
 *      timeout, requiring uid=0 and context u:r:magisk:s0 in the output
 *      (the restore script's own success banner is never accepted);
 *   3. getenforce == Enforcing AND the stage4-enforcing completion marker
 *      for THIS boot present in the after-boot log;
 *   4. the kernel boot id read from /proc itself; a caller-supplied boot
 *      id must match it, and the self-read value is what gets signed;
 *   5. the challenge is recorded in the used-challenge ledger (append +
 *      fsync) BEFORE signing; a (bootId, challenge) pair is signed at
 *      most once, across both modes;
 *   6. genesis mode additionally requires the operator token file
 *      (custody/genesis-approved, content == this boot id), which is
 *      deleted (consumed) before the signature is produced. Routine mode
 *      never signs a genesis message and genesis mode never signs a
 *      routine message; the mode is chosen by argv, never by request
 *      content.
 * Any gate failure: no signature, the denial is appended to the custody
 * log, exit code 3.
 *
 * Custody (design section 2.2): the key pair is generated ON-DEVICE by
 * keygen mode. The PKCS#8 private key (proof-key.der) never leaves the
 * custody directory /data/snusnu_root/signer (root:root 0700, key 0400);
 * only the X.509 public key (proof-key.pub.der) is exported for pinning.
 * Keygen refuses to overwrite an existing key.
 *
 * Delivery (design section 2.5): the two-line proof drop (message /
 * signature hex, the Stage4ProofDrop wire format) is written to a custody
 * temp file, fsynced, renamed into the app DPS proof-drop/ directory, and
 * then label-fixed: owner u0_a55, and the SELinux label copied from the
 * journal-family file in the same directory (so the MCS categories
 * c55,c256,c512,c768 measured on 2026-11-01 are preserved). If the fixup
 * cannot be applied, the drop is removed again and the run fails closed:
 * a proof the app cannot read is not left behind as a false success.
 *
 * Modes:
 *   keygen <pubOut.der>          generate custody key pair (refuses if set)
 *   report                       measure and print every gate fact; never signs
 *   sign-proof <bootId> <challengeHex>
 *   sign-proof-request           routine proof; boot+challenge are read
 *                                from the service's proof_request file
 *   sign-genesis <challengeHex>  requires + consumes the operator token
 *
 * Exit codes: 0 ok, 2 usage, 3 denied by a gate, 4 I/O or delivery failure.
 */
public final class Stage4DeviceSigner {
    private Stage4DeviceSigner() {}

    // ---- configuration (production defaults; host tests override) ----
    private static String prop(String key, String fallback) {
        String value = System.getProperty(key);
        return value == null || value.length() == 0 ? fallback : value;
    }

    private static final String CUSTODY = prop("snu.signer.custody",
            "/data/snusnu_root/signer");
    private static final String SU_BIN = prop("snu.signer.su", "/sbin/su");
    private static final String GETENFORCE_BIN = prop("snu.signer.getenforce",
            "/system/bin/getenforce");
    private static final String BOOT_ID_PATH = prop("snu.signer.boot_id_path",
            "/proc/sys/kernel/random/boot_id");
    private static final String STATUS_PATH = prop("snu.signer.status_path",
            "/proc/self/status");
    private static final String ATTR_PATH = prop("snu.signer.attr_path",
            "/proc/self/attr/current");
    private static final String MARKER_PATH = prop("snu.signer.marker_path",
            "/data/adb/stage4-enforcing-after-boot.log");
    private static final String REQUEST_PATH = prop("snu.signer.request_path",
            "/data/cache/snusnu/state/proof_request");
    private static final String DPS_FILES = prop("snu.signer.dps_files",
            "/data/user_de/0/io.github.voidnullvalue.snusnuroot.persistence"
                    + "/files");
    private static final String FIXUP = prop("snu.signer.fixup", "exec");
    private static final String CHOWN_BIN = prop("snu.signer.chown",
            "/system/bin/chown");
    private static final String CHCON_BIN = prop("snu.signer.chcon",
            "/system/bin/chcon");
    private static final String LS_BIN = prop("snu.signer.ls",
            "/system/bin/ls");
    private static final long SU_TIMEOUT_SECONDS =
            Long.parseLong(prop("snu.signer.su_timeout", "20"));

    private static final String APP_UID_NAME = "u0_a55";
    private static final String EXPECTED_CONTEXT = "u:r:magisk:s0";
    private static final String PRIVATE_KEY_NAME = "proof-key.der";
    private static final String PUBLIC_KEY_NAME = "proof-key.pub.der";
    private static final String LEDGER_NAME = "used-challenges.log";
    private static final String TOKEN_NAME = "genesis-approved";
    private static final String LOG_NAME = "signer.log";
    private static final String PROOF_DROP_NAME = "stage4-proof.txt";
    private static final String GENESIS_DROP_NAME = "stage4-genesis.txt";
    private static final String BUILD_ID = "PS7331.4463N";
    private static final String INCREMENTAL = "0031575863172";

    private static final Pattern BOOT_PATTERN = Pattern.compile(
            "[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}");
    private static final Pattern HEX64_PATTERN = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern LABEL_PATTERN = Pattern.compile(
            "u:object_r:app_data_file:s0(:c[0-9]+(,c[0-9]+)*)?");

    // ---- small helpers ----

    private static String readFileTrimmed(File file) {
        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            String text = new String(bytes, StandardCharsets.UTF_8);
            StringBuilder cleaned = new StringBuilder(text.length());
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c != '\0') cleaned.append(c);
            }
            return cleaned.toString().trim();
        } catch (IOException | RuntimeException error) {
            return null;
        }
    }

    private static String firstLine(File file) {
        String text = readFileTrimmed(file);
        if (text == null) return null;
        int newline = text.indexOf('\n');
        return (newline < 0 ? text : text.substring(0, newline)).trim();
    }

    private static void fsyncFile(File file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        try {
            in.getFD().sync();
        } finally {
            in.close();
        }
    }

    private static void fsyncDir(File dir) {
        try {
            FileInputStream in = new FileInputStream(dir);
            try {
                in.getFD().sync();
            } finally {
                in.close();
            }
        } catch (IOException | RuntimeException ignored) {
            // Directory fsync is best-effort from Java; the journal performs
            // its own durability discipline on the records that matter.
        }
    }

    private static void writeFileFsync(File file, byte[] content)
            throws IOException {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(content);
            out.flush();
            out.getFD().sync();
        } finally {
            out.close();
        }
    }

    private static void log(String line) {
        String entry = System.currentTimeMillis() + " " + line + "\n";
        try {
            File custody = new File(CUSTODY);
            if (custody.isDirectory()) {
                FileOutputStream out = new FileOutputStream(
                        new File(custody, LOG_NAME), true);
                try {
                    out.write(entry.getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    out.getFD().sync();
                } finally {
                    out.close();
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // Logging must never change a deny into a sign or vice versa.
        }
        System.out.println("SIGNER " + line);
    }

    private static int deny(String mode, String reason) {
        log("DENY mode=" + mode + " reason=" + reason);
        System.out.println("SIGNER_RESULT DENY mode=" + mode
                + " reason=" + reason);
        return 3;
    }

    private static final class ExecResult {
        final int rc;
        final String out;
        ExecResult(int rc, String out) {
            this.rc = rc;
            this.out = out;
        }
    }

    /** Runs a command with a hard timeout; null on timeout/spawn failure. */
    private static ExecResult exec(String[] command, long timeoutSeconds) {
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.redirectErrorStream(true);
            process = builder.start();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            InputStream stream = process.getInputStream();
            byte[] chunk = new byte[4096];
            long deadline = System.nanoTime()
                    + TimeUnit.SECONDS.toNanos(timeoutSeconds);
            while (true) {
                while (stream.available() > 0) {
                    int read = stream.read(chunk);
                    if (read < 0) break;
                    buffer.write(chunk, 0, read);
                }
                if (!process.isAlive()) break;
                if (System.nanoTime() > deadline) {
                    process.destroyForcibly();
                    return null;
                }
                try {
                    Thread.sleep(20L);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    process.destroyForcibly();
                    return null;
                }
            }
            int read;
            while ((read = stream.read(chunk)) >= 0) {
                buffer.write(chunk, 0, read);
            }
            return new ExecResult(process.exitValue(),
                    new String(buffer.toByteArray(), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException error) {
            if (process != null) process.destroyForcibly();
            return null;
        }
    }

    // ---- self-attestation facts (design section 2.4) ----

    private static Integer ownUid() {
        String text = readFileTrimmed(new File(STATUS_PATH));
        if (text == null) return null;
        BufferedReader reader = new BufferedReader(new java.io.StringReader(text));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Uid:")) {
                    String[] parts = line.substring(4).trim().split("\\s+");
                    return Integer.valueOf(parts[0]);
                }
            }
        } catch (IOException | RuntimeException error) {
            return null;
        }
        return null;
    }

    private static String ownContext() {
        return readFileTrimmed(new File(ATTR_PATH));
    }

    private static String ownBootId() {
        String value = firstLine(new File(BOOT_ID_PATH));
        if (value == null || !BOOT_PATTERN.matcher(value).matches()) {
            return null;
        }
        return value;
    }

    private static boolean suCheckPasses() {
        ExecResult result = exec(
                new String[]{SU_BIN, "-c", "id"}, SU_TIMEOUT_SECONDS);
        if (result == null || result.rc != 0 || result.out == null) {
            return false;
        }
        return result.out.contains("uid=0(")
                && result.out.contains("context=" + EXPECTED_CONTEXT);
    }

    private static boolean enforcingRestored(String bootId) {
        ExecResult result = exec(new String[]{GETENFORCE_BIN}, 10L);
        if (result == null || result.rc != 0 || result.out == null
                || !"Enforcing".equals(result.out.trim())) {
            return false;
        }
        String marker = readFileTrimmed(new File(MARKER_PATH));
        if (marker == null) return false;
        String needle = "boot=" + bootId + " OK enforcing-restored";
        for (String line : marker.split("\n")) {
            if (line.contains(needle)) return true;
        }
        return false;
    }

    /** All signing gates. Returns null when every gate passes. */
    private static String gateFailure(boolean genesisMode) {
        Integer uid = ownUid();
        if (uid == null || uid.intValue() != 0) return "own_uid";
        if (!EXPECTED_CONTEXT.equals(ownContext())) return "own_context";
        if (!suCheckPasses()) return "su_measurement";
        String bootId = ownBootId();
        if (bootId == null) return "boot_id_unreadable";
        if (!enforcingRestored(bootId)) return "enforcing_not_restored";
        return null;
    }

    // ---- used-challenge ledger (design section 2.4 item 5) ----

    private static File ledgerFile() {
        return new File(CUSTODY, LEDGER_NAME);
    }

    private static boolean ledgerContains(String bootId, String challenge)
            throws IOException {
        File ledger = ledgerFile();
        if (!ledger.isFile()) return false;
        String text = readFileTrimmed(ledger);
        if (text == null) throw new IOException("ledger unreadable");
        for (String line : text.split("\n")) {
            String[] parts = line.trim().split(" ");
            if (parts.length >= 2 && parts[0].equals(bootId)
                    && parts[1].equals(challenge)) {
                return true;
            }
        }
        return false;
    }

    private static void ledgerAppend(String bootId, String challenge,
            String mode) throws IOException {
        File ledger = ledgerFile();
        String line = bootId + " " + challenge + " " + mode + " "
                + System.currentTimeMillis() + "\n";
        FileOutputStream out = new FileOutputStream(ledger, true);
        try {
            out.write(line.getBytes(StandardCharsets.UTF_8));
            out.flush();
            out.getFD().sync();
        } finally {
            out.close();
        }
    }

    // ---- keys ----

    private static PrivateKey loadPrivateKey() throws Exception {
        byte[] der = Files.readAllBytes(
                new File(CUSTODY, PRIVATE_KEY_NAME).toPath());
        PrivateKey key = KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
        if (!(key instanceof ECPrivateKey)
                || ((ECPrivateKey) key).getParams().getCurve().getField()
                        .getFieldSize() != 256) {
            throw new IllegalStateException("custody key is not EC P-256");
        }
        return key;
    }

    private static String signHex(PrivateKey key, String message)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] raw = signature.sign();
        StringBuilder hex = new StringBuilder(raw.length * 2);
        for (byte b : raw) {
            hex.append(Character.forDigit((b >>> 4) & 15, 16));
            hex.append(Character.forDigit(b & 15, 16));
        }
        return hex.toString();
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(Character.forDigit((b >>> 4) & 15, 16));
            hex.append(Character.forDigit(b & 15, 16));
        }
        return hex.toString();
    }

    // ---- delivery + label fixup (design section 2.5) ----

    /**
     * Label source, in trust order: a journal-family file already carrying
     * the app's real label (MCS categories included) in the same directory.
     */
    private static File labelReference() {
        String[] candidates = {
            "stage4-genesis-challenge.state",
            "stage4-native-attempt-v2.state",
            "stage4-boot-guard.state",
        };
        File files = new File(DPS_FILES);
        for (String name : candidates) {
            File candidate = new File(files, name);
            if (candidate.isFile()) return candidate;
        }
        return files.isDirectory() ? files : null;
    }

    private static boolean fixup(File target, boolean directory) {
        if ("skip".equals(FIXUP)) {
            log("FIXUP_SKIPPED target=" + target);
            return true;
        }
        if ("print".equals(FIXUP)) {
            File reference = labelReference();
            System.out.println("FIXUP_PLAN " + CHOWN_BIN + " "
                    + APP_UID_NAME + " " + target);
            System.out.println("FIXUP_PLAN " + CHCON_BIN
                    + " <label-copied-from "
                    + (reference == null ? "<none>" : reference.toString())
                    + "> " + target);
            return true;
        }
        ExecResult chown = exec(
                new String[]{CHOWN_BIN, APP_UID_NAME, target.toString()}, 10L);
        if (chown == null || chown.rc != 0) return false;
        File reference = labelReference();
        if (reference == null) return false;
        ExecResult listed = exec(
                new String[]{LS_BIN, "-Z", reference.toString()}, 10L);
        if (listed == null || listed.rc != 0 || listed.out == null) {
            return false;
        }
        String label = listed.out.trim().split("\\s+")[0];
        if (!LABEL_PATTERN.matcher(label).matches()) return false;
        ExecResult chcon = exec(
                new String[]{CHCON_BIN, label, target.toString()}, 10L);
        return chcon != null && chcon.rc == 0;
    }

    /**
     * Writes the two-line drop into the app DPS proof-drop directory.
     * Returns false (and removes the drop) when delivery or fixup fails.
     */
    private static boolean deliver(String dropName, String message,
            String signatureHex) {
        File files = new File(DPS_FILES);
        File dropDir = new File(files, "proof-drop");
        boolean createdDir = false;
        if (!dropDir.isDirectory()) {
            createdDir = dropDir.mkdirs();
            if (!dropDir.isDirectory()) {
                log("DELIVERY_FAIL mkdir " + dropDir);
                return false;
            }
        }
        File temp = new File(CUSTODY, dropName + ".tmp");
        File target = new File(dropDir, dropName);
        try {
            String content = message + "\n" + signatureHex + "\n";
            writeFileFsync(temp, content.getBytes(StandardCharsets.UTF_8));
            if (!temp.renameTo(target)) {
                log("DELIVERY_FAIL rename " + target);
                temp.delete();
                return false;
            }
            fsyncDir(dropDir);
        } catch (IOException | RuntimeException error) {
            log("DELIVERY_FAIL io " + error);
            temp.delete();
            return false;
        }
        if (createdDir && !fixup(dropDir, true)) {
            log("DELIVERY_FAIL dir_fixup " + dropDir);
            target.delete();
            return false;
        }
        if (!fixup(target, false)) {
            log("DELIVERY_FAIL fixup " + target);
            target.delete();
            return false;
        }
        log("DELIVERED " + target);
        return true;
    }

    // ---- modes ----

    private static int keygen(String pubOutPath) {
        Integer uid = ownUid();
        if (uid == null || uid.intValue() != 0) {
            return deny("keygen", "own_uid");
        }
        File custody = new File(CUSTODY);
        try {
            if (!custody.isDirectory()) {
                if (!custody.mkdirs()) {
                    System.out.println("SIGNER_RESULT FAIL mode=keygen"
                            + " reason=custody_missing");
                    return 4;
                }
                try {
                    Files.setPosixFilePermissions(custody.toPath(),
                            PosixFilePermissions.fromString("rwx------"));
                } catch (RuntimeException ignored) {
                    // The installer enforces custody permissions; keygen
                    // only refuses to proceed on a key collision.
                }
            }
            File privateFile = new File(custody, PRIVATE_KEY_NAME);
            if (privateFile.exists()) {
                return deny("keygen", "key_already_exists");
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            byte[] privateDer = pair.getPrivate().getEncoded();
            byte[] publicDer = pair.getPublic().getEncoded();
            writeFileFsync(privateFile, privateDer);
            try {
                Files.setPosixFilePermissions(privateFile.toPath(),
                        PosixFilePermissions.fromString("r--------"));
            } catch (RuntimeException ignored) {
                // Enforced by the install step (root:root 0400).
            }
            writeFileFsync(new File(custody, PUBLIC_KEY_NAME), publicDer);
            writeFileFsync(new File(pubOutPath), publicDer);
            fsyncDir(custody);
            log("KEYGEN pub_sha256=" + sha256Hex(publicDer));
            System.out.println("SIGNER_RESULT OK mode=keygen pub_sha256="
                    + sha256Hex(publicDer) + " pub_path=" + pubOutPath);
            return 0;
        } catch (Exception error) {
            log("KEYGEN_FAIL " + error);
            System.out.println("SIGNER_RESULT FAIL mode=keygen reason=io");
            return 4;
        }
    }

    private static int report() {
        Integer uid = ownUid();
        String context = ownContext();
        String bootId = ownBootId();
        boolean su = suCheckPasses();
        boolean enforcing = bootId != null && enforcingRestored(bootId);
        System.out.println("FACT uid=" + uid);
        System.out.println("FACT context=" + context);
        System.out.println("FACT su_measurement=" + (su ? "pass" : "fail"));
        System.out.println("FACT boot_id=" + bootId);
        System.out.println("FACT enforcing_restored="
                + (enforcing ? "pass" : "fail"));
        System.out.println("FACT custody_key="
                + (new File(CUSTODY, PRIVATE_KEY_NAME).isFile()
                        ? "present" : "absent"));
        boolean all = uid != null && uid.intValue() == 0
                && EXPECTED_CONTEXT.equals(context) && su && enforcing
                && bootId != null;
        log("REPORT all_gates=" + (all ? "pass" : "fail"));
        System.out.println("SIGNER_RESULT " + (all ? "OK" : "DENY")
                + " mode=report");
        return all ? 0 : 3;
    }

    private static int sign(String mode, String requestedBoot,
            String challenge) {
        boolean genesis = "sign-genesis".equals(mode);
        if (challenge == null || !HEX64_PATTERN.matcher(challenge).matches()) {
            return deny(mode, "challenge_format");
        }
        if (!genesis && (requestedBoot == null
                || !BOOT_PATTERN.matcher(requestedBoot).matches())) {
            return deny(mode, "boot_format");
        }
        String gate = gateFailure(genesis);
        if (gate != null) return deny(mode, gate);
        String bootId = ownBootId();
        if (!genesis && !bootId.equals(requestedBoot)) {
            return deny(mode, "boot_mismatch");
        }
        File token = new File(CUSTODY, TOKEN_NAME);
        if (genesis) {
            String tokenBoot = firstLine(token);
            if (tokenBoot == null || !tokenBoot.equals(bootId)) {
                return deny(mode, "operator_token");
            }
        }
        try {
            if (ledgerContains(bootId, challenge)) {
                return deny(mode, "challenge_reused");
            }
            ledgerAppend(bootId, challenge, genesis ? "genesis" : "root");
        } catch (IOException error) {
            log("LEDGER_FAIL " + error);
            System.out.println("SIGNER_RESULT FAIL mode=" + mode
                    + " reason=ledger_io");
            return 4;
        }
        if (genesis) {
            // Consume the operator token before producing the signature:
            // a failed attempt can never be retried on the same token.
            token.delete();
            fsyncDir(new File(CUSTODY));
        }
        String message = genesis
                ? "stage4-genesis-v1|" + bootId + "|" + challenge + "|"
                        + BUILD_ID + "|" + INCREMENTAL
                        + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing"
                : "stage4-root-v1|" + bootId + "|" + challenge
                        + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
        try {
            PrivateKey key = loadPrivateKey();
            String signatureHex = signHex(key, message);
            boolean delivered = deliver(
                    genesis ? GENESIS_DROP_NAME : PROOF_DROP_NAME,
                    message, signatureHex);
            if (!delivered) {
                System.out.println("SIGNER_RESULT FAIL mode=" + mode
                        + " reason=delivery");
                return 4;
            }
            log("SIGNED mode=" + mode + " boot=" + bootId);
            System.out.println("SIGNER_RESULT OK mode=" + mode
                    + " boot=" + bootId);
            return 0;
        } catch (Exception error) {
            log("SIGN_FAIL mode=" + mode + " " + error);
            System.out.println("SIGNER_RESULT FAIL mode=" + mode
                    + " reason=sign_io");
            return 4;
        }
    }

    private static int signFromRequest() {
        String request = firstLine(new File(REQUEST_PATH));
        if (request == null) return deny("sign-proof-request", "no_request");
        String[] parts = request.split("\\s+");
        if (parts.length != 2) {
            return deny("sign-proof-request", "request_format");
        }
        return sign("sign-proof", parts[0], parts[1]);
    }

    public static void main(String[] args) {
        if (args.length >= 1 && "keygen".equals(args[0])
                && args.length == 2) {
            System.exit(keygen(args[1]));
        }
        if (args.length == 1 && "report".equals(args[0])) {
            System.exit(report());
        }
        if (args.length == 3 && "sign-proof".equals(args[0])) {
            System.exit(sign("sign-proof", args[1], args[2]));
        }
        if (args.length == 1 && "sign-proof-request".equals(args[0])) {
            System.exit(signFromRequest());
        }
        if (args.length == 2 && "sign-genesis".equals(args[0])) {
            System.exit(sign("sign-genesis", null, args[1]));
        }
        System.err.println("usage: keygen <pubOut.der> | report |"
                + " sign-proof <bootId> <challengeHex> | sign-proof-request"
                + " | sign-genesis <challengeHex>");
        System.exit(2);
    }
}
