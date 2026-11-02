# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub private vulnerability reporting:
**Security** tab > **Report a vulnerability** on <https://github.com/jsundquist/sbom>. Do not open a public issue or PR for a
security problem.

Include the affected version or commit, reproduction steps, and the impact you expect.

## Supported versions

Only the latest `main` (and the images built from it) is supported. Fixes land on `main`; there are no backports.

## Response time

This is a personal project maintained on a best-effort basis. Expect an acknowledgement within 7 days and a status update
or fix plan within 30 days. Coordinated disclosure is welcome; please allow time for a fix before publishing details.

## Release integrity

Every push to `main` publishes two images, `ghcr.io/jsundquist/sbom` and `ghcr.io/jsundquist/sbom-worker`
(`.github/workflows/release.yml`). Each image, addressed by digest, has:

- a keyless cosign signature (Sigstore, signed by the release workflow's GitHub OIDC identity),
- signed SLSA build provenance, and
- a signed CycloneDX SBOM attestation of the image contents.

Verify an image (resolve its digest first):

```sh
DIGEST=$(docker buildx imagetools inspect ghcr.io/jsundquist/sbom:<tag> --format '{{.Manifest.Digest}}')

gh attestation verify "oci://ghcr.io/jsundquist/sbom@${DIGEST}" --owner jsundquist

cosign verify "ghcr.io/jsundquist/sbom@${DIGEST}" \
  --certificate-identity-regexp '^https://github.com/jsundquist/sbom/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use `sbom-worker` for the worker image.

### SLSA level

The build meets SLSA Build L2: a hosted platform (GitHub Actions) generates and signs the provenance. It is not L3,
because the build is not run in an isolated, reusable-workflow builder whose signing material is out of reach of the
build steps. The deploy tag in k8s-gitops is still pinned by tag, not by digest.
