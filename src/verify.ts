import * as crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import {verify as sigstoreVerify} from 'sigstore'
import {TOOL_REPO_OWNER, TOOL_REPO_NAME} from './constants'

/**
 * Betterleaks releases are signed keylessly by their own release workflow via
 * GitHub Actions OIDC. Verification pins BOTH the OIDC issuer and the exact
 * signing identity.
 *
 * Pinning the identity is not optional. Anyone can mint a valid Fulcio
 * signature over any file, so a signature that verifies without an identity
 * check proves only "somebody signed this" -- see the `certificateIdentityURI`
 * note on verifyChecksumsSignature.
 */
export const SIGSTORE_ISSUER = 'https://token.actions.githubusercontent.com'
export const RELEASE_WORKFLOW_REF = '.github/workflows/release.yml'

/** Name of the digest marker written alongside a verified cached binary. */
export const DIGEST_MARKER = '.betterleaks.sha256'

/**
 * Strict semver. Rejects the path-traversal payloads that would otherwise let
 * `version` walk out of the pinned release path and pull a binary from an
 * arbitrary repo, and guarantees the value is safe to interpolate into the
 * expected signing identity.
 */
export const VERSION_RE = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/

export function assertValidVersion(version: string): void {
  if (!VERSION_RE.test(version)) {
    throw new Error(
      `Invalid version "${version}": expected a semver version such as v1.8.1`
    )
  }
}

/**
 * The SAN URI Fulcio embeds for a release-workflow signature. Because the
 * identity carries the tag, an exact match also binds the signature to the
 * specific version being installed.
 */
export function expectedIdentity(tag: string): string {
  return (
    `https://github.com/${TOOL_REPO_OWNER}/${TOOL_REPO_NAME}` +
    `/${RELEASE_WORKFLOW_REF}@refs/tags/${tag}`
  )
}

export function sha256File(filePath: string): string {
  return crypto
    .createHash('sha256')
    .update(fs.readFileSync(filePath))
    .digest('hex')
    .toLowerCase()
}

/**
 * Verifies that `checksumsPath` is the checksums.txt signed by the betterleaks
 * release workflow for `tag`. Throws on any failure -- callers must not
 * downgrade this to a warning.
 *
 * Both options below are required. sigstore-js silently ignores unknown
 * options, so cosign's `--certificate-identity-regexp` spelling does nothing
 * here; and with no identity options at all, verification passes for any
 * validly signed artifact.
 */
export async function verifyChecksumsSignature(
  checksumsPath: string,
  bundlePath: string,
  tag: string,
  tufCachePath?: string
): Promise<void> {
  let bundle: unknown
  try {
    bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf-8'))
  } catch {
    throw new Error(`Invalid Sigstore bundle at ${bundlePath}: not valid JSON`)
  }

  const artifact = fs.readFileSync(checksumsPath)

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await sigstoreVerify(bundle as any, artifact, {
      certificateIssuer: SIGSTORE_ISSUER,
      certificateIdentityURI: expectedIdentity(tag),
      ...(tufCachePath ? {tufCachePath} : {})
    })
  } catch (error) {
    // sigstore-js buries the real cause (e.g. blocked egress to
    // tuf-repo-cdn.sigstore.dev) two levels down, which makes CI failures
    // opaque. Unwrap it.
    throw new Error(
      `Signature verification failed for checksums.txt (${tag}): ${describeError(error)}`
    )
  }
}

function describeError(error: unknown): string {
  const parts: string[] = []
  let current: unknown = error
  for (let depth = 0; current instanceof Error && depth < 4; depth++) {
    parts.push(current.message)
    current = (current as Error).cause
  }
  return parts.length > 0 ? parts.join(' <- ') : 'unknown error'
}

/**
 * Looks up `assetName` in an already-verified checksums.txt and compares its
 * digest against the downloaded archive. Returns the verified digest.
 *
 * Only call this after verifyChecksumsSignature has passed: on its own, a
 * checksums file published in the same release as the binary defends against
 * corruption in transit, not against whoever can replace release assets.
 */
export function assertArchiveDigest(
  archivePath: string,
  checksumsPath: string,
  assetName: string
): string {
  const entry = fs
    .readFileSync(checksumsPath, 'utf-8')
    .split('\n')
    .map(line => line.trim().split(/\s+/))
    .find(fields => fields.length >= 2 && fields[1] === assetName)

  if (!entry) {
    throw new Error(
      `No checksum entry for ${assetName} in verified checksums.txt`
    )
  }

  const expected = entry[0].toLowerCase()
  const actual = sha256File(archivePath)

  if (expected !== actual) {
    throw new Error(
      `Digest mismatch for ${assetName}: expected ${expected}, got ${actual}`
    )
  }

  return actual
}

/**
 * checksums.txt covers the release archive, not the binary extracted from it,
 * so a cached binary cannot be re-checked against it. Record the extracted
 * binary's own digest at first install instead.
 */
export function writeDigestMarker(cachedDir: string, binaryPath: string): void {
  fs.writeFileSync(
    path.join(cachedDir, DIGEST_MARKER),
    `${sha256File(binaryPath)}\n`,
    'utf-8'
  )
}

/**
 * Re-checks a cached binary against its marker. Returns false for a missing
 * marker, a missing binary, or a mismatch, so callers can treat an
 * unverifiable cache entry as a miss rather than trusting it.
 *
 * SCOPE -- this is trust-on-first-use, not an upstream guarantee. The marker is
 * a digest we computed ourselves after verifying the release; nothing upstream
 * attests to it. Anyone who can write to RUNNER_TOOL_CACHE can rewrite the
 * marker as easily as the binary, so this detects an unmarked or naively
 * swapped entry, NOT a deliberate attacker with cache write access.
 *
 * For a tool cache shared across jobs or repositories (self-hosted runners),
 * the cache itself is a trust boundary: either stop sharing it, or skip the
 * cache and re-verify from upstream on every run.
 */
export function verifyCachedBinary(
  cachedDir: string,
  binaryPath: string
): boolean {
  const markerPath = path.join(cachedDir, DIGEST_MARKER)
  if (!fs.existsSync(markerPath) || !fs.existsSync(binaryPath)) {
    return false
  }
  const expected = fs.readFileSync(markerPath, 'utf-8').trim().toLowerCase()
  return expected !== '' && expected === sha256File(binaryPath)
}
