"""Execute the actual Java journal against HOST-ONLY Android test doubles.

Models journal state, atomic rename and injected sync failure. The Android API
is faked, so this is NOT a real device or power-failure durability test.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
JDK = Path('/opt/homebrew/opt/openjdk@17/bin')
JAVA_SOURCES = {
    'io/github/voidnullvalue/snusnuroot/persistence/Stage4BootIdentity.java': r'''
package io.github.voidnullvalue.snusnuroot.persistence;
final class Stage4BootIdentity {
    static String readCurrentBootId() {
        return System.getProperty("snu.test.boot.id",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    }
}
''',
    'android/content/Context.java': r'''
package android.content;
import java.io.File;
public class Context {
    private final File dir;
    public Context(File dir) {this.dir=dir;}
    public Context createDeviceProtectedStorageContext(){return this;}
    public File getFilesDir(){return dir;}
}
''',
    'android/util/AtomicFile.java': r'''
package android.util;
import java.io.*;
import java.nio.file.*;
public class AtomicFile {
    private final File base;
    private final File newer;
    public AtomicFile(File base){this.base=base;this.newer=new File(base.getPath()+".new");}
    public byte[] readFully() throws IOException {return Files.readAllBytes(base.toPath());}
    public FileOutputStream startWrite() throws IOException {
        return new FileOutputStream(newer);
    }
    public void finishWrite(FileOutputStream stream) {
        try {
            stream.getFD().sync(); stream.close();
            Files.move(newer.toPath(),base.toPath(),
                StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } catch(IOException e){throw new RuntimeException(e);}
    }
    public void failWrite(FileOutputStream stream) {
        try{stream.close();}catch(IOException ignored){}
        newer.delete();
    }
}
''',
    'android/system/ErrnoException.java': r'''
package android.system;
public class ErrnoException extends Exception {
    public ErrnoException(String m){super(m);}
}
''',
    'android/system/StructStat.java': r'''
package android.system;
public final class StructStat {
    public final int st_mode;
    public StructStat(int mode){this.st_mode=mode;}
}
''',
    'android/system/OsConstants.java': r'''
package android.system;
public final class OsConstants {
    public static final int O_RDONLY=0, O_NOFOLLOW=131072, S_IFDIR=16384;
    public static boolean S_ISDIR(int mode){return (mode & 61440) == S_IFDIR;}
}
''',
    'android/system/Os.java': r'''
package android.system;
import java.io.FileDescriptor;
import java.nio.file.*;
public final class Os {
    public static boolean failNextFsync=false;
    public static boolean notDirectory=false;
    public static int syncCount=0;
    public static FileDescriptor open(String path,int flags,int mode) throws ErrnoException {
        if(!Files.isDirectory(Paths.get(path)) || Files.isSymbolicLink(Paths.get(path)))
            throw new ErrnoException("not an actual directory");
        return new FileDescriptor();
    }
    public static StructStat fstat(FileDescriptor fd){
        return new StructStat(notDirectory ? 32768 : 16384);
    }
    public static void fsync(FileDescriptor fd) throws ErrnoException {
        ++syncCount;
        if (failNextFsync) {failNextFsync=false;throw new ErrnoException("injected-fsync-error");}
    }
    public static void close(FileDescriptor fd) throws ErrnoException {}
}
''',
    'HostJournalHarness.java': r'''
import android.content.Context;
import android.system.Os;
import io.github.voidnullvalue.snusnuroot.persistence.Stage4AttemptJournal;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
public class HostJournalHarness {
    static final String A="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    static final String B="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    static final String C="cccccccc-cccc-cccc-cccc-cccccccccccc";
    static File sandbox;
    static void check(boolean truth,String why){if(!truth)throw new AssertionError(why);}
    static File makeFolder(String name) throws Exception {
        File folder=new File(sandbox,name);
        check(folder.mkdir(),"sandbox folder created");
        return folder;
    }
    static Path file(File dir){return new File(dir,"stage4-native-attempt.state").toPath();}
    static void record(File dir,String state) throws Exception {
        Files.write(file(dir),state.getBytes(StandardCharsets.UTF_8));
    }
    static String saved(File dir) throws Exception {
        return new String(Files.readAllBytes(file(dir)),StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        check(args.length==1,"explicit owned test sandbox required");
        sandbox=new File(args[0]);
        check(sandbox.isDirectory(),"test sandbox not present");
        File none=makeFolder("missing");
        check(!new Stage4AttemptJournal(new Context(none)).beginOneShot(B),"missing must deny");
        System.out.println("PASS missing-denies");

        File good=makeFolder("good");
        record(good,"READY:"+A);
        Stage4AttemptJournal j=new Stage4AttemptJournal(new Context(good));
        check(!j.beginOneShot(A),"same boot denied");
        check(!j.beginOneShot("not-a-uuid"),"bad boot denied");
        check(j.beginOneShot(B),"single transition accepted");
        check(saved(good).equals("INFLIGHT:"+B),"durable marker changed");
        check(!j.beginOneShot(B),"same object retried");
        check(!new Stage4AttemptJournal(new Context(good)).beginOneShot(C),
            "new process instance must deny after in-flight");
        check(Os.syncCount>0,"parent sync invoked");
        System.out.println("PASS one-shot-and-restart");

        File bad=makeFolder("corrupt");
        record(bad,"READY:"+A+"JUNK");
        check(!new Stage4AttemptJournal(new Context(bad)).beginOneShot(B),"corrupt denied");
        record(bad,"TRUNCATED");
        check(!new Stage4AttemptJournal(new Context(bad)).beginOneShot(B),"truncated denied");
        record(bad,"READY:"+A+"\\n");
        check(!new Stage4AttemptJournal(new Context(bad)).beginOneShot(B),
            "trailing newline must not become permit");
        System.out.println("PASS corrupt-denies");

        File failedSync=makeFolder("fsync-fail");
        record(failedSync,"READY:"+A);
        Os.failNextFsync=true;
        check(!new Stage4AttemptJournal(new Context(failedSync)).beginOneShot(B),
            "failed fsync cannot authorize launch");
        check(saved(failedSync).equals("INFLIGHT:"+B),
            "sync failure conservatively leaves inflight");
        check(!new Stage4AttemptJournal(new Context(failedSync)).beginOneShot(C),
            "sync failure never retries after process recreation");
        System.out.println("PASS injected-fsync-denies");

        File notdir=makeFolder("fstat-fail");
        record(notdir,"READY:"+A);
        Os.notDirectory=true;
        check(!new Stage4AttemptJournal(new Context(notdir)).beginOneShot(B),
            "descriptor is not a directory");
        Os.notDirectory=false;
        System.out.println("PASS directory-type-check");

        File parallel=makeFolder("parallel");
        record(parallel,"READY:"+A);
        AtomicInteger launches=new AtomicInteger();
        CountDownLatch go=new CountDownLatch(1);
        ExecutorService pool=Executors.newFixedThreadPool(8);
        Future<?>[] tasks=new Future[8];
        for(int i=0;i<8;i++) {
            tasks[i]=pool.submit(()->{
                try {
                    go.await();
                    if(new Stage4AttemptJournal(new Context(parallel)).beginOneShot(B))
                        launches.incrementAndGet();
                } catch(Exception e){throw new RuntimeException(e);}
            });
        }
        go.countDown();
        for(Future<?> task:tasks)task.get(10,TimeUnit.SECONDS);
        pool.shutdown();
        check(launches.get()==1,"at most one caller can obtain permit");
        System.out.println("PASS same-process-eight-thread-race");
    }
}
'''
}


class ActualJavaJournalHostExecution(unittest.TestCase):
    def test_java_journal_atomic_transitions_and_faults(self):
        javac = JDK/'javac'
        java = JDK/'java'
        self.assertTrue(javac.is_file() and java.is_file(), 'JDK 17 is required')
        with tempfile.TemporaryDirectory(prefix='snu-journal-jvm-') as tmp:
            base = Path(tmp)
            for path, content in JAVA_SOURCES.items():
                dest = base/'src'/path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
            journal = base/'src/io/github/voidnullvalue/snusnuroot/persistence/Stage4AttemptJournal.java'
            journal.parent.mkdir(parents=True, exist_ok=True)
            journal.write_bytes((ROOT/'review/firehd10-actor-journal/Stage4AttemptJournal.java').read_bytes())
            (journal.parent/'Stage4ProofVerifier.java').write_bytes(
                (ROOT/'review/firehd10-actor-journal/Stage4ProofVerifier.java').read_bytes())
            classes = base/'classes'
            compile_result = subprocess.run([
                str(javac), '--release', '8', '-encoding', 'UTF-8', '-d', str(classes),
                *[str(p) for p in (base/'src').rglob('*.java')],
            ], capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            output = subprocess.run([str(java), '-cp', str(classes), 'HostJournalHarness',
                                     str(base)],
                                    text=True, capture_output=True, timeout=30, check=False)
            self.assertEqual(output.returncode, 0, output.stderr)
            self.assertEqual(len(output.stdout.splitlines()), 6, output.stdout)
            self.assertTrue(all(x.startswith('PASS ') for x in output.stdout.splitlines()),
                            output.stdout)


if __name__ == '__main__':
    unittest.main()
