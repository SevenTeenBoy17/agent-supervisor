# Maintainer release procedure

1. Update `VERSION`, Python package metadata, core CLI output, both adapter versions, and
   `CHANGELOG.md` to the same release.
2. Run focused security regressions, the full test suite, deterministic bundle build, and
   package metadata checks in a clean checkout.
3. Scan the current tree and full Git history for credentials, private keys, tokens,
   webhooks, raw prompts, state, logs, and personal paths. Rotate any real secret ever
   committed. The scanner resolves Git only through the machine-local trusted executable
   registry described in the installation guide; CI creates a job-local, ephemeral,
   runner-owned registry immediately before scanning and never commits it.
4. Review the exact base/head/diff. Test changes require a separate integrity review.
5. Build from a clean checkout with line-ending conversion disabled. The identity JSON
   is local validation data and must not be uploaded:

   ```powershell
   $Head = (git rev-parse HEAD).Trim()
   git -c core.autocrlf=false clone --no-checkout --no-hardlinks . ../agent-supervisor-release-build
   git -C ../agent-supervisor-release-build -c core.autocrlf=false checkout --detach $Head
   Set-Location ../agent-supervisor-release-build
   python bin/build-core-release-manifest.py --root . --version 3.1.6 --output .ci-artifacts/agent-supervisor-3.1.6.zip --identity-output .ci-artifacts/release-identity.json
   python -m pip wheel . --no-deps --wheel-dir .ci-artifacts
   ```

   Inspect the ZIP with `inspect_runtime_bundle`; confirm that `LICENSE` and `NOTICE`
   exactly match the reviewed source files. Hash both public assets. Upload only
   `agent-supervisor-3.1.6.zip` and
   `agent_supervisor_core-3.1.6-py3-none-any.whl`.
6. Verify a clean working tree except for ignored release artifacts, sign/tag the
   exact reviewed commit, push the branch and tag without force, and create a GitHub
   Release from that tag. Publishing is an outward action and requires explicit approval.
7. Re-open the public repository and release URLs anonymously or through the GitHub API;
   verify visibility, tag/commit identity, license detection, and downloadable artifacts.

Never build from an ambient global adapter installation. Release tests and review inputs
must resolve to this repository snapshot.
