package io.github.voidnullvalue.snusnuroot.persistence;

/** Strip kernel address disclosures while retaining diagnostic result codes. */
final class NativeOutputSanitizer {
    private NativeOutputSanitizer() { }

    static String redact(String result) {
        if (result == null) return "null";
        // Kernel object addresses are printed by the upstream hwbinder probe
        // as labeled file/node/ptr fields. Codes such as
        // HWBINDER_STATEFUL result=0x5000003d00000000 must remain intact so
        // classification (ENODATA vs successful kernel write) still works.
        return result.replaceAll(
                "(?i)\\b(file|node|ptr|addr|address|kernel_addr)\\s*=\\s*0x[0-9a-f]+",
                "$1=[redacted]");
    }
}
