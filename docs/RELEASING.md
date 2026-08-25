# Maintainer release procedure

1. Update `VERSION`, Python package metadata, core CLI output, both adapter versions, and
   `CHANGELOG.md` to the same release.
2. Run focused security regressions, the full test suite, deterministic bundle build, and
   package metadata checks in a clean checkout.
3. Scan the current tree and full Git history for credentials, private keys, tokens,
   webhooks, raw prompts, state, logs, and personal paths. Rotate any real secret ever
   committed.
4. Review the exact base/head/diff. Test changes require a separate integrity review.
5. Build without publishing a pointer:

   ```powershell
   python bin/build-core-release-manifest.py --root . --version 3.1.6 --output runtime/supervisor-runtime.zip --identity-output runtime/release-identity.json
   ```

6. Verify a clean working tree except for intentional release artifacts, sign/tag the
   exact reviewed commit, push the branch and tag without force, and create a GitHub
   Release from that tag. Publishing is an outward action and requires explicit approval.
7. Re-open the public repository and release URLs anonymously or through the GitHub API;
   verify visibility, tag/commit identity, license detection, and downloadable artifacts.

Never build from an ambient global adapter installation. Release tests and review inputs
must resolve to this repository snapshot.

