# Security

Device and application authorization are enforced by the core and the existing authenticated owner IPC, independently of renderer requests. Recovery refuses unknown ownership, changed interface identity and reparse paths. Internet sharing stays off by default and must fail closed when authorization, source, upstream or cleanup proof is lost.

Do not publish tokens, device serials, paired-device data, captured traffic or raw recovery journals. For a security report, provide a minimal synthetic reproduction, affected source paths and version. Contact the eventual repository maintainer privately; this prepared local repository does not yet have a published reporting address.

Signing keys and release credentials are never part of the build. Public signing verification keys are compatibility contracts and are intentionally retained.

End-user builds remove developer remote maintenance, upgrade discovery and remote installation. Historical consent cannot enable these endpoints. Use local installers to update; see [release scope](docs/RELEASE-SCOPE.md).
