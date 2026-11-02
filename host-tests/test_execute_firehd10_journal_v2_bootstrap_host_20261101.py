"""Execute the v2 journal (genesis bootstrap + proof completion) on the host.

Compiles the REAL v2 classes from the journal-gated implementation tree
against the standard host Android doubles, generates an ephemeral EC key
pair, pins its public half through the real gen_pinned_key.py, and drives
genesis / begin / completion / lockout-recovery scenarios with real ECDSA
signatures from the host reference signer.

This proves host-side protocol behaviour only. It does NOT prove Android
storage durability, SELinux behaviour, signer custody, or that any
signature was produced by a process really holding MagiskSU uid=0.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest

from test_execute_firehd10_journal_on_host_20261014 import JAVA_SOURCES, ROOT, JDK


V2_TREE = (ROOT / 'build/journal-gated-implementation-20261101/v2')
V2_PKG = (V2_TREE / 'stage4-persistent/app/src/io/github/voidnullvalue'
          '/snusnuroot/persistence')
V2_CLASSES = ('Stage4AttemptJournalV2.java', 'Stage4GenesisVerifier.java',
              'Stage4BootWitness.java', 'Stage4ProofDrop.java',
              'Stage4ProofVerifier.java')

# Same host double as October's, except the kernel boot id can also be
# "unreadable" (property NONE -> null), which is the stock-policy reality
# the v2 design has to survive.
BOOT_IDENTITY_STUB = r'''
package io.github.voidnullvalue.snusnuroot.persistence;
final class Stage4BootIdentity {
    static String readCurrentBootId() {
        String value = System.getProperty("snu.test.boot.id", "NONE");
        return "NONE".equals(value) ? null : value;
    }
}
'''

HARNESS = r'''
import android.content.Context;
import android.system.Os;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4AttemptJournalV2;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4BootWitness;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4PinnedProofKey;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4ProofDrop;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class HostJournalV2Harness {
    static final String A="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    static final String B="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    static final String C="cccccccc-cccc-cccc-cccc-cccccccccccc";
    static final String D="dddddddd-dddd-dddd-dddd-dddddddddddd";
    static final String E="eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
    static File sandbox;
    static Path priv;
    static PublicKey pub;
    static void check(boolean good,String message) {
        if(!good)throw new AssertionError(message);
    }
    static File folder(String name) throws Exception {
        File dir=new File(sandbox,name);
        check(dir.mkdir(),"test dir absent");
        return dir;
    }
    static Stage4AttemptJournalV2 journal(File dir) {
        return new Stage4AttemptJournalV2(new Context(dir));
    }
    static String state(File dir) throws Exception {
        Path file=new File(dir,"stage4-native-attempt-v2.state").toPath();
        return Files.exists(file)
            ? new String(Files.readAllBytes(file),StandardCharsets.UTF_8)
            : "<absent>";
    }
    static void setProc(String boot) {
        System.setProperty("snu.test.boot.id", boot==null ? "NONE" : boot);
    }
    static String[] root(String boot,String challenge) throws Exception {
        return HostReferenceSigner.signRoot(priv,boot,challenge);
    }
    static String[] genesis(String boot,String challenge) throws Exception {
        return HostReferenceSigner.signGenesis(priv,boot,challenge);
    }
    static String signRaw(String message) throws Exception {
        Signature signature=Signature.getInstance("SHA256withECDSA");
        signature.initSign(HostReferenceSigner.loadPrivate(priv));
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] raw=signature.sign();
        StringBuilder hex=new StringBuilder();
        for(byte b:raw) hex.append(String.format("%02x",b & 255));
        return hex.toString();
    }

    public static void main(String[] args) throws Exception {
        check(args.length==2,"sandbox and private key arguments");
        sandbox=new File(args[0]);
        check(sandbox.isDirectory(),"host temp dir absent");
        priv=Paths.get(args[1]);
        pub=Stage4PinnedProofKey.publicKey();

        // 1: an empty journal can never begin.
        File d1=folder("s01");
        setProc(A);
        check(journal(d1).beginOneShot(A,100)==null,"empty must deny begin");
        check("EMPTY".equals(journal(d1).stateKind()),"kind must be EMPTY");
        System.out.println("PASS empty-begin-denied");

        // 2: genesis without an issued challenge denies even a signed proof.
        File d2=folder("s02");
        String[] g2=genesis(A,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        check(!journal(d2).installGenesis(A,100,pub,g2[0],g2[1]),
                "genesis requires an issued challenge");
        check("EMPTY".equals(journal(d2).stateKind()),"still empty");
        System.out.println("PASS genesis-without-challenge-denied");

        // 3: genesis happy path, idempotent issuance, replay denied.
        File d3=folder("s03");
        setProc(A);
        String ch3=journal(d3).issueGenesisChallenge();
        check(ch3!=null && ch3.matches("[0-9a-f]{64}"),"challenge issued");
        check(ch3.equals(journal(d3).issueGenesisChallenge()),
                "issuance must be idempotent while unconsumed");
        String[] g3=genesis(A,ch3);
        check(journal(d3).installGenesis(A,100,pub,g3[0],g3[1]),
                "valid genesis must install READY");
        check(state(d3).equals("READY:"+A+":100"),"READY bound to genesis");
        check(!new File(d3,"stage4-genesis-challenge.state").exists(),
                "challenge must be consumed");
        check(!journal(d3).installGenesis(A,100,pub,g3[0],g3[1]),
                "genesis replay on READY must deny");
        System.out.println("PASS genesis-happy-and-replay-denied");

        // 4: genesis signed by a different key denies and consumes.
        File d4=folder("s04");
        setProc(A);
        String ch4=journal(d4).issueGenesisChallenge();
        KeyPairGenerator gen=KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair other=gen.generateKeyPair();
        String msg4=HostReferenceSigner.genesisMessage(A,ch4);
        Signature sig4=Signature.getInstance("SHA256withECDSA");
        sig4.initSign(other.getPrivate());
        sig4.update(msg4.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex4=new StringBuilder();
        for(byte b:sig4.sign()) hex4.append(String.format("%02x",b & 255));
        check(!journal(d4).installGenesis(A,100,pub,msg4,hex4.toString()),
                "wrong key must deny genesis");
        check("EMPTY".equals(journal(d4).stateKind()),"still empty");
        check(!new File(d4,"stage4-genesis-challenge.state").exists(),
                "failed genesis must still consume the challenge");
        System.out.println("PASS genesis-wrong-key-denied");

        // 5: genesis for a different firmware build denies.
        File d5=folder("s05");
        setProc(A);
        String ch5=journal(d5).issueGenesisChallenge();
        String msg5="stage4-genesis-v1|"+A+"|"+ch5
            +"|PS7331.4460N|0031575863172|uid=0|ctx=u:r:magisk:s0|selinux=Enforcing";
        check(!journal(d5).installGenesis(A,100,pub,msg5,signRaw(msg5)),
                "genesis is bound to the exact build");
        System.out.println("PASS genesis-wrong-build-denied");

        // 6: same-boot begin denied (boot equality and count latch).
        setProc(A);
        check(journal(d3).beginOneShot(A,100)==null,"same boot+count denied");
        check(journal(d3).beginOneShot(A,101)==null,
                "same boot denied even with a newer count");
        check(state(d3).equals("READY:"+A+":100"),"READY untouched");
        System.out.println("PASS begin-same-boot-denied");

        // 7: next-boot begin issues the attempt challenge exactly once.
        setProc(B);
        String chB=journal(d3).beginOneShot(B,101);
        check(chB!=null && chB.matches("[0-9a-f]{64}"),"challenge issued");
        check(state(d3).equals("INFLIGHT:"+B+":101:"+chB+":"+A),
                "INFLIGHT binds boot, count, challenge, previous boot");
        check(journal(d3).beginOneShot(C,102)==null,"second begin denied");
        System.out.println("PASS begin-next-boot-issues-challenge");

        // 8: completion with a proof for the wrong challenge denies.
        String[] wrong=root(B,"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        check(!journal(d3).completeWithSignedProof(B,101,pub,wrong[0],wrong[1]),
                "challenge binding must hold");
        check(state(d3).startsWith("INFLIGHT:"),"INFLIGHT preserved");
        System.out.println("PASS completion-wrong-challenge-denied");

        // 9: completion with a proof for a different boot denies.
        String[] cross=root(D,chB);
        check(!journal(d3).completeWithSignedProof(B,101,pub,cross[0],cross[1]),
                "proof boot must equal the inflight boot");
        System.out.println("PASS completion-cross-boot-denied");

        // 10: completion happy path; the same proof cannot replay.
        String[] ok=root(B,chB);
        check(journal(d3).completeWithSignedProof(B,101,pub,ok[0],ok[1]),
                "valid proof completes the attempt");
        check(state(d3).equals("READY:"+B+":101"),"READY bound to proven boot");
        check(!journal(d3).completeWithSignedProof(B,101,pub,ok[0],ok[1]),
                "proof replay on READY denied");
        System.out.println("PASS completion-happy-and-replay-denied");

        // 11: lockout after an uncompleted attempt; only genesis recovers.
        File d11=folder("s11");
        setProc(A);
        String chg=journal(d11).issueGenesisChallenge();
        String[] gg=genesis(A,chg);
        check(journal(d11).installGenesis(A,100,pub,gg[0],gg[1]),"genesis");
        setProc(B);
        String chB11=journal(d11).beginOneShot(B,101);
        check(chB11!=null,"begin in B");
        setProc(C);
        check(journal(d11).beginOneShot(C,102)==null,"lockout denies begin");
        String[] stale=root(B,chB11);
        check(!journal(d11).completeWithSignedProof(C,102,pub,stale[0],stale[1]),
                "a later boot must not launder a stale INFLIGHT");
        String chr=journal(d11).issueGenesisChallenge();
        check(chr!=null,"recovery challenge issuable from INFLIGHT");
        String[] routine=root(C,chr);
        check(!journal(d11).recoverLockoutWithGenesis(C,102,pub,routine[0],routine[1]),
                "a routine proof must not clear a lockout");
        String chr2=journal(d11).issueGenesisChallenge();
        check(chr2!=null && !chr2.equals(chr),
                "the failed attempt consumed the challenge; a fresh one issues");
        String[] rec=genesis(C,chr2);
        check(journal(d11).recoverLockoutWithGenesis(C,102,pub,rec[0],rec[1]),
                "genesis proof recovers the lockout");
        check(state(d11).equals("READY:"+C+":102"),"READY after recovery");
        System.out.println("PASS lockout-genesis-recovery-only");

        // 12: foreign records deny everything and are preserved byte-exact.
        File d12=folder("s12");
        setProc(B);
        Path statePath=new File(d12,"stage4-native-attempt-v2.state").toPath();
        Files.write(statePath,("READY:"+A).getBytes(StandardCharsets.UTF_8));
        check(journal(d12).beginOneShot(B,101)==null,"v1 format is foreign");
        Files.write(statePath,"HELLO".getBytes(StandardCharsets.UTF_8));
        check(journal(d12).issueGenesisChallenge()==null,
                "foreign state refuses challenge issuance");
        check(journal(d12).beginOneShot(B,101)==null,"foreign denies begin");
        check(!journal(d12).installGenesis(B,101,pub,"x","y"),
                "foreign denies genesis");
        check(new String(Files.readAllBytes(statePath),StandardCharsets.UTF_8)
                .equals("HELLO"),"foreign bytes preserved");
        System.out.println("PASS foreign-record-preserved");

        // 13: boot-count latch rejects equal and regressed counts.
        File d13=folder("s13");
        setProc(A);
        String ch13=journal(d13).issueGenesisChallenge();
        String[] g13=genesis(A,ch13);
        check(journal(d13).installGenesis(A,100,pub,g13[0],g13[1]),"genesis");
        setProc(B);
        check(journal(d13).beginOneShot(B,100)==null,"equal count denied");
        check(journal(d13).beginOneShot(B,99)==null,"regressed count denied");
        System.out.println("PASS boot-count-latch");

        // 14: degraded identity mode (no witness, no readable kernel id).
        File d14=folder("s14");
        setProc(A);
        String ch14=journal(d14).issueGenesisChallenge();
        String[] g14=genesis(A,ch14);
        check(journal(d14).installGenesis(A,100,pub,g14[0],g14[1]),"genesis");
        check(!journal(d14).installGenesis(null,101,pub,g14[0],g14[1]),
                "genesis never runs degraded (and READY denies anyway)");
        setProc(null);
        String chD=journal(d14).beginOneShot(null,101);
        check(chD!=null,"degraded begin allowed by count latch");
        check(state(d14).equals("INFLIGHT:?:101:"+chD+":"+A),
                "degraded INFLIGHT binds unknown boot plus previous boot");
        String[] prev=root(A,chD);
        check(!journal(d14).completeWithSignedProof(null,101,pub,prev[0],prev[1]),
                "proof for the PREVIOUS boot must not complete degraded");
        String[] fresh=root(E,chD);
        check(journal(d14).completeWithSignedProof(null,101,pub,fresh[0],fresh[1]),
                "proof for a new boot completes degraded mode");
        check(state(d14).equals("READY:"+E+":101"),"READY takes proven boot");
        System.out.println("PASS degraded-identity-flow");

        // 15: witness/kernel contradiction denies begin and completion.
        File d15=folder("s15");
        setProc(A);
        String ch15=journal(d15).issueGenesisChallenge();
        String[] g15=genesis(A,ch15);
        check(journal(d15).installGenesis(A,100,pub,g15[0],g15[1]),"genesis");
        setProc(C);
        check(journal(d15).beginOneShot(D,101)==null,
                "witness D contradicting kernel C denies begin");
        String ch15b=journal(d15).beginOneShot(C,101);
        check(ch15b!=null,"begin with agreeing witness");
        String[] p15=root(C,ch15b);
        setProc(D);
        check(!journal(d15).completeWithSignedProof(C,101,pub,p15[0],p15[1]),
                "kernel D contradicting witness C denies completion");
        System.out.println("PASS identity-contradiction-denied");

        // 16: eight racing begins produce exactly one challenge.
        File d16=folder("s16");
        setProc(A);
        String ch16=journal(d16).issueGenesisChallenge();
        String[] g16=genesis(A,ch16);
        check(journal(d16).installGenesis(A,100,pub,g16[0],g16[1]),"genesis");
        setProc(B);
        ExecutorService pool=Executors.newFixedThreadPool(8);
        CountDownLatch go=new CountDownLatch(1);
        AtomicInteger issued=new AtomicInteger();
        Future<?>[] jobs=new Future[8];
        for(int i=0;i<8;i++) jobs[i]=pool.submit(()->{
            try{
                go.await();
                if(journal(d16).beginOneShot(B,101)!=null)
                    issued.incrementAndGet();
            }catch(Exception error){throw new RuntimeException(error);}
        });
        go.countDown();
        for(Future<?> job:jobs)job.get(10,TimeUnit.SECONDS);
        pool.shutdown();
        check(issued.get()==1,"exactly one begin may win the race");
        System.out.println("PASS begin-race-single-winner");

        // 17: a failed parent-directory sync denies genesis.
        File d17=folder("s17");
        setProc(A);
        String ch17=journal(d17).issueGenesisChallenge();
        String[] g17=genesis(A,ch17);
        Os.failNextFsync=true;
        check(!journal(d17).installGenesis(A,100,pub,g17[0],g17[1]),
                "fsync failure must deny genesis");
        System.out.println("PASS genesis-fsync-failure-denies");

        // 18: mailbox drop and witness parsers are strict.
        String[] any=root(B,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        byte[] good=(any[0]+"\n"+any[1]+"\n").getBytes(StandardCharsets.UTF_8);
        Stage4ProofDrop.Drop drop=Stage4ProofDrop.parse(good);
        check(drop!=null && drop.message.equals(any[0])
                && drop.signatureHex.equals(any[1]),"valid drop parses");
        check(Stage4ProofDrop.parse((any[0]+"\n"+any[1]+"\nextra\n")
                .getBytes(StandardCharsets.UTF_8))==null,"extra line rejected");
        check(Stage4ProofDrop.parse((any[0]+"\r\n"+any[1])
                .getBytes(StandardCharsets.UTF_8))==null,"CR rejected");
        Stage4BootWitness.Witness wit=Stage4BootWitness.parseLines(B,"12.5",false);
        check(wit!=null && B.equals(wit.bootId) && wit.uptimeSeconds==12.5,
                "valid witness parses");
        check(Stage4BootWitness.parseLines(B,"12.5",true)==null,
                "extra witness line rejected");
        check(Stage4BootWitness.parseLines("nope","12.5",false)==null,
                "bad witness uuid rejected");
        check(Stage4BootWitness.isFresh(wit,20000L),"fresh witness accepted");
        check(!Stage4BootWitness.isFresh(
                Stage4BootWitness.parseLines(B,"30.0",false),20000L),
                "witness from a later uptime is impossible this boot");
        check(!Stage4BootWitness.isFresh(
                Stage4BootWitness.parseLines(B,null,false),20000L),
                "witness without uptime is not fresh");
        System.out.println("PASS drop-and-witness-parsers-strict");

        // 19: the pinned key source round-trips to the generated DER.
        byte[] der=Files.readAllBytes(new File(sandbox,"pub.der").toPath());
        check(java.util.Arrays.equals(der,pub.getEncoded()),
                "pinned key must decode to the generated public key");
        System.out.println("PASS pinned-key-roundtrip");
    }
}
'''

EXPECTED_PASS = 19


class JournalV2BootstrapHostTests(unittest.TestCase):
    def test_v2_journal_genesis_completion_and_lockout(self):
        javac = JDK / 'javac'
        java = JDK / 'java'
        self.assertTrue(javac.is_file() and java.is_file(),
                        'JDK 17 is required')
        with tempfile.TemporaryDirectory(
                prefix='snu-journal-v2-host-') as directory:
            root = Path(directory)
            sources = dict(JAVA_SOURCES)
            sources.pop('HostJournalHarness.java')
            sources['io/github/voidnullvalue/snusnuroot/persistence/'
                    'Stage4BootIdentity.java'] = BOOT_IDENTITY_STUB
            for relative, source in sources.items():
                output = root / 'src' / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(source)
            package = (root / 'src/io/github/voidnullvalue/snusnuroot'
                       '/persistence')
            package.mkdir(parents=True, exist_ok=True)
            for name in V2_CLASSES:
                (package / name).write_bytes((V2_PKG / name).read_bytes())
            (root / 'src/HostReferenceSigner.java').write_bytes(
                (V2_TREE / 'host-reference/HostReferenceSigner.java')
                .read_bytes())

            classes = root / 'classes'
            signer_build = subprocess.run(
                [str(javac), '--release', '8', '-encoding', 'UTF-8',
                 '-d', str(classes),
                 str(root / 'src/HostReferenceSigner.java')],
                capture_output=True, text=True, timeout=40)
            self.assertEqual(signer_build.returncode, 0, signer_build.stderr)
            keygen = subprocess.run(
                [str(java), '-cp', str(classes), 'HostReferenceSigner',
                 'keygen', str(root / 'pub.der'), str(root / 'priv.der')],
                capture_output=True, text=True, timeout=25)
            self.assertEqual(keygen.returncode, 0, keygen.stderr)

            pin = subprocess.run(
                ['python3', str(V2_TREE / 'gen_pinned_key.py'),
                 str(root / 'pub.der'),
                 'HOST TEST KEY - NOT THE DEVICE KEY',
                 str(package / 'Stage4PinnedProofKey.java')],
                capture_output=True, text=True, timeout=25)
            self.assertEqual(pin.returncode, 0, pin.stderr)

            (root / 'src/HostJournalV2Harness.java').write_text(HARNESS)
            build = subprocess.run(
                [str(javac), '--release', '8', '-encoding', 'UTF-8',
                 '-d', str(classes),
                 *map(str, (root / 'src').rglob('*.java'))],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run(
                [str(java), '-cp', str(classes), 'HostJournalV2Harness',
                 str(root), str(root / 'priv.der')],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stderr)
            lines = [line for line in run.stdout.splitlines() if line]
            self.assertEqual(len(lines), EXPECTED_PASS, run.stdout)
            self.assertTrue(
                all(line.startswith('PASS ') for line in lines), run.stdout)


if __name__ == '__main__':
    unittest.main()
