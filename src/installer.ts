import * as core from '@actions/core'
import * as tc from '@actions/tool-cache'
import {HttpClient} from '@actions/http-client'
import * as path from 'path'
import {
  TOOL_NAME,
  TOOL_REPO_OWNER,
  TOOL_REPO_NAME,
  getAssetName,
  getBinaryName
} from './constants'
import {
  assertArchiveDigest,
  assertValidVersion,
  verifyCachedBinary,
  verifyChecksumsSignature,
  writeDigestMarker
} from './verify'

interface GitHubRelease {
  tag_name: string
}

function stripVPrefix(version: string): string {
  return version.startsWith('v') ? version.slice(1) : version
}

function ensureVPrefix(version: string): string {
  return version.startsWith('v') ? version : `v${version}`
}

export async function resolveVersion(
  version: string,
  token: string
): Promise<string> {
  if (version !== 'latest') {
    // Validate before the value reaches any URL or signing identity.
    assertValidVersion(version)
    return ensureVPrefix(version)
  }

  const http = new HttpClient('betterleaks-action')
  const headers: Record<string, string> = {}
  if (token) {
    headers['Authorization'] = `token ${token}`
  }

  const url = `https://api.github.com/repos/${TOOL_REPO_OWNER}/${TOOL_REPO_NAME}/releases/latest`
  const response = await http.getJson<GitHubRelease>(url, headers)

  if (response.statusCode === 403) {
    throw new Error(
      'GitHub API rate limit exceeded. Provide a github-token input for authenticated requests.'
    )
  }

  if (response.statusCode !== 200 || !response.result) {
    throw new Error(
      `Failed to resolve latest version: HTTP ${response.statusCode}`
    )
  }

  // The API response is not trusted input either.
  const tag = response.result.tag_name
  assertValidVersion(tag)
  return tag
}

/** Base URL for a release's assets. `tag` must already be validated. */
function getReleaseBaseUrl(tag: string): string {
  return `https://github.com/${TOOL_REPO_OWNER}/${TOOL_REPO_NAME}/releases/download/${tag}`
}

export function getDownloadUrl(
  version: string,
  platform: string,
  arch: string
): string {
  assertValidVersion(version)
  const assetName = getAssetName(stripVPrefix(version), platform, arch)
  return `${getReleaseBaseUrl(ensureVPrefix(version))}/${assetName}`
}

export async function install(
  version: string,
  token: string
): Promise<string> {
  const platform = process.platform
  const arch = process.arch
  const resolvedVersion = await resolveVersion(version, token)
  const numericVersion = stripVPrefix(resolvedVersion)
  const tag = ensureVPrefix(resolvedVersion)

  // Check tool cache first. A cache entry is only usable if it still matches
  // the digest recorded when it was verified -- the tool cache persists across
  // jobs on self-hosted runners, so an unverifiable entry is treated as a miss.
  const cachedPath = tc.find(TOOL_NAME, numericVersion, arch)
  if (cachedPath) {
    const cachedBinary = path.join(cachedPath, getBinaryName(platform))
    if (verifyCachedBinary(cachedPath, cachedBinary)) {
      core.info(`Found cached betterleaks ${numericVersion} (digest verified)`)
      return cachedBinary
    }
    core.warning(
      `Cached betterleaks ${numericVersion} failed digest verification; re-downloading`
    )
  }

  const baseUrl = getReleaseBaseUrl(tag)
  const assetName = getAssetName(numericVersion, platform, arch)

  core.info(`Downloading betterleaks ${tag} from ${baseUrl}/${assetName}`)
  const archivePath = await tc.downloadTool(
    `${baseUrl}/${assetName}`,
    undefined,
    token ? `token ${token}` : undefined
  )
  const checksumsPath = await tc.downloadTool(`${baseUrl}/checksums.txt`)
  const bundlePath = await tc.downloadTool(
    `${baseUrl}/checksums.txt.sigstore.json`
  )

  // Verify BEFORE extracting: unpacking an unverified archive is itself the
  // attack surface being closed here. Both calls throw, and main() turns that
  // into a failed step, so this fails closed.
  await verifyChecksumsSignature(
    checksumsPath,
    bundlePath,
    tag,
    process.env['BETTERLEAKS_TUF_CACHE']
  )
  const digest = assertArchiveDigest(archivePath, checksumsPath, assetName)
  core.info(
    `Verified ${assetName} (sha256:${digest}), signed by the ${tag} release workflow`
  )

  // Extract
  let extractedPath: string
  if (platform === 'win32') {
    extractedPath = await tc.extractZip(archivePath)
  } else {
    extractedPath = await tc.extractTar(archivePath)
  }

  // Cache
  const cachedDir = await tc.cacheDir(
    extractedPath,
    TOOL_NAME,
    numericVersion,
    arch
  )
  const binaryPath = path.join(cachedDir, getBinaryName(platform))

  // Ensure executable
  if (platform !== 'win32') {
    const {chmod} = await import('fs/promises')
    await chmod(binaryPath, 0o755)
  }

  // Record the extracted binary's digest so later cache hits can be re-checked.
  writeDigestMarker(cachedDir, binaryPath)

  core.info(`Betterleaks ${resolvedVersion} installed to ${binaryPath}`)
  return binaryPath
}
