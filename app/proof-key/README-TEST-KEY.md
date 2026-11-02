# proof-key/test-public.der — HOST TEST KEY, NOT THE DEVICE KEY

X.509 DER of an EC P-256 public key generated on the Mac on 2026-11-01
solely so the v2 host build has a syntactically valid pinned key for
`Stage4PinnedProofKey` (see `../build-v2.sh`).

The matching private key was written to a temporary file during
generation, never copied into this tree or the diagnostics project, and
deleted in the same session. **Nobody can produce a valid proof
signature for an APK built with this pin.** That is intentional: the
device key is generated on the device during the genesis session and
pinned by rebuilding (runbook addendum, Phase G). An APK carrying this
test pin is a host artifact only; `device_ready` remains false.
