import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * HOST TEST REFERENCE SIGNER - NOT THE DEVICE SIGNER.
 *
 * This class exists only so host unit tests can drive the v2 journal's
 * genesis / completion transitions end to end with real ECDSA signatures.
 * It implements NO custody, NO self-attestation gating, and NO on-device
 * behaviour. The device signer's custody and gating contract is specified
 * in FIREHD10_JOURNAL_BOOTSTRAP_AND_PROOF_CUSTODY_DESIGN_20261101.md
 * section 2. Never copy this class, or any key it handles, to a device.
 *
 * CLI:
 *   keygen <pub.der> <priv.der>
 *   sign-root    <priv.der> <bootId> <challengeHex>  -> message \n sigHex
 *   sign-genesis <priv.der> <bootId> <challengeHex>  -> message \n sigHex
 */
public final class HostReferenceSigner {
    private HostReferenceSigner() {}

    static String rootMessage(String bootId, String challenge) {
        return "stage4-root-v1|" + bootId + "|" + challenge
                + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
    }

    static String genesisMessage(String bootId, String challenge) {
        // Build pins mirror Stage4GenesisVerifier (PS7331.4463N).
        return "stage4-genesis-v1|" + bootId + "|" + challenge
                + "|PS7331.4463N|0031575863172"
                + "|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
    }

    static String sign(PrivateKey key, String message) throws Exception {
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

    static PrivateKey loadPrivate(Path der) throws Exception {
        byte[] bytes = Files.readAllBytes(der);
        return KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    static String[] signRoot(Path privDer, String bootId, String challenge)
            throws Exception {
        String message = rootMessage(bootId, challenge);
        return new String[]{message, sign(loadPrivate(privDer), message)};
    }

    static String[] signGenesis(Path privDer, String bootId,
            String challenge) throws Exception {
        String message = genesisMessage(bootId, challenge);
        return new String[]{message, sign(loadPrivate(privDer), message)};
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 3 && "keygen".equals(args[0])) {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = gen.generateKeyPair();
            Files.write(Paths.get(args[1]), pair.getPublic().getEncoded());
            Files.write(Paths.get(args[2]), pair.getPrivate().getEncoded());
            System.out.println("keypair written");
            return;
        }
        if (args.length == 4 && "sign-root".equals(args[0])) {
            String[] out = signRoot(Paths.get(args[1]), args[2], args[3]);
            System.out.println(out[0]);
            System.out.println(out[1]);
            return;
        }
        if (args.length == 4 && "sign-genesis".equals(args[0])) {
            String[] out = signGenesis(Paths.get(args[1]), args[2], args[3]);
            System.out.println(out[0]);
            System.out.println(out[1]);
            return;
        }
        System.err.println("usage: keygen|sign-root|sign-genesis ...");
        System.exit(2);
    }
}
