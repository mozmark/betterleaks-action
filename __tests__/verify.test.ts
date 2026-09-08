import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import {
  DIGEST_MARKER,
  SIGSTORE_ISSUER,
  assertArchiveDigest,
  assertValidVersion,
  expectedIdentity,
  sha256File,
  verifyCachedBinary,
  verifyChecksumsSignature,
  writeDigestMarker
} from '../src/verify'

jest.mock('sigstore', () => ({verify: jest.fn()}))
// eslint-disable-next-line @typescript-eslint/no-var-requires
const sigstore = require('sigstore') as {verify: jest.Mock}

let tmp: string

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-test-'))
  sigstore.verify.mockReset()
  sigstore.verify.mockResolvedValue(undefined)
})

afterEach(() => {
  fs.rmSync(tmp, {recursive: true, force: true})
})

function write(name: string, content: string): string {
  const p = path.join(tmp, name)
  fs.writeFileSync(p, content)
  return p
}

describe('assertValidVersion', () => {
  it('accepts plain and v-prefixed semver', () => {
    expect(() => assertValidVersion('v1.8.1')).not.toThrow()
    expect(() => assertValidVersion('1.8.1')).not.toThrow()
    expect(() => assertValidVersion('v1.8.1-rc.1')).not.toThrow()
  })

  it('rejects the path-traversal payload that escapes the pinned repo', () => {
    expect(() =>
      assertValidVersion(
        'v1/../../../../../ATTACKER/EVIL/releases/download/v9/payload.tar.gz?i='
      )
    ).toThrow(/Invalid version/)
  })

  it('rejects other non-semver input', () => {
    for (const bad of ['latest', '', 'v1', 'v1.8', '../v1.8.1', 'v1.8.1/..']) {
      expect(() => assertValidVersion(bad)).toThrow(/Invalid version/)
    }
  })
})

describe('expectedIdentity', () => {
  it('builds the release-workflow SAN URI for the tag', () => {
    expect(expectedIdentity('v1.8.1')).toBe(
      'https://github.com/betterleaks/betterleaks/.github/workflows/release.yml@refs/tags/v1.8.1'
    )
  })
})

describe('verifyChecksumsSignature', () => {
  function setup(): {checksums: string; bundle: string} {
    return {
      checksums: write('checksums.txt', 'abc  betterleaks_1.8.1_linux_x64.tar.gz\n'),
      bundle: write('bundle.json', '{"mediaType":"x"}')
    }
  }

  // Regression test for the trap: sigstore-js silently ignores unknown
  // options, so passing cosign's --certificate-identity-regexp spelling (or no
  // identity at all) verifies the signature without checking WHO signed it.
  // Anyone can mint a valid Fulcio signature, so that is not verification.
  it('pins both the issuer and the exact signing identity', async () => {
    const {checksums, bundle} = setup()
    await verifyChecksumsSignature(checksums, bundle, 'v1.8.1')

    expect(sigstore.verify).toHaveBeenCalledTimes(1)
    const opts = sigstore.verify.mock.calls[0][2]
    expect(opts.certificateIssuer).toBe(SIGSTORE_ISSUER)
    expect(opts.certificateIdentityURI).toBe(expectedIdentity('v1.8.1'))
    expect(opts).not.toHaveProperty('certificateIdentityRegExp')
  })

  it('propagates verification failure and unwraps the underlying cause', async () => {
    const {checksums, bundle} = setup()
    const inner = new Error('getaddrinfo ENOTFOUND tuf-repo-cdn.sigstore.dev')
    const outer = new Error('error refreshing TUF metadata', {cause: inner})
    sigstore.verify.mockRejectedValue(outer)

    await expect(
      verifyChecksumsSignature(checksums, bundle, 'v1.8.1')
    ).rejects.toThrow(/error refreshing TUF metadata <- getaddrinfo ENOTFOUND/)
  })

  it('rejects a malformed bundle', async () => {
    const checksums = write('checksums.txt', 'abc  asset\n')
    const bundle = write('bundle.json', 'not json')
    await expect(
      verifyChecksumsSignature(checksums, bundle, 'v1.8.1')
    ).rejects.toThrow(/not valid JSON/)
    expect(sigstore.verify).not.toHaveBeenCalled()
  })
})

describe('assertArchiveDigest', () => {
  const asset = 'betterleaks_1.8.1_linux_x64.tar.gz'

  it('returns the digest when it matches', () => {
    const archive = write(asset, 'binary-content')
    const digest = sha256File(archive)
    const checksums = write('checksums.txt', `${digest}  ${asset}\n`)
    expect(assertArchiveDigest(archive, checksums, asset)).toBe(digest)
  })

  it('throws on a mismatched digest', () => {
    const archive = write(asset, 'tampered-content')
    const checksums = write('checksums.txt', `${'0'.repeat(64)}  ${asset}\n`)
    expect(() => assertArchiveDigest(archive, checksums, asset)).toThrow(
      /Digest mismatch/
    )
  })

  it('throws when the asset is absent from checksums.txt', () => {
    const archive = write(asset, 'content')
    const checksums = write(
      'checksums.txt',
      `${'0'.repeat(64)}  betterleaks_1.8.1_darwin_arm64.tar.gz\n`
    )
    expect(() => assertArchiveDigest(archive, checksums, asset)).toThrow(
      /No checksum entry/
    )
  })

  it('selects the correct line among several platforms', () => {
    const archive = write(asset, 'linux-content')
    const digest = sha256File(archive)
    const checksums = write(
      'checksums.txt',
      [
        `${'1'.repeat(64)}  betterleaks_1.8.1_darwin_arm64.tar.gz`,
        `${digest}  ${asset}`,
        `${'2'.repeat(64)}  betterleaks_1.8.1_windows_x64.zip`,
        ''
      ].join('\n')
    )
    expect(assertArchiveDigest(archive, checksums, asset)).toBe(digest)
  })
})

describe('cached binary verification', () => {
  it('accepts a cache entry matching its marker', () => {
    const binary = write('betterleaks', 'binary')
    writeDigestMarker(tmp, binary)
    expect(verifyCachedBinary(tmp, binary)).toBe(true)
  })

  it('rejects a cache entry whose binary was swapped after caching', () => {
    const binary = write('betterleaks', 'binary')
    writeDigestMarker(tmp, binary)
    fs.writeFileSync(binary, 'malicious-replacement')
    expect(verifyCachedBinary(tmp, binary)).toBe(false)
  })

  it('rejects a cache entry with no marker', () => {
    const binary = write('betterleaks', 'binary')
    expect(verifyCachedBinary(tmp, binary)).toBe(false)
  })

  it('rejects a marker with no binary', () => {
    fs.writeFileSync(path.join(tmp, DIGEST_MARKER), `${'0'.repeat(64)}\n`)
    expect(verifyCachedBinary(tmp, path.join(tmp, 'betterleaks'))).toBe(false)
  })
})
