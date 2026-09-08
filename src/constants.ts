export const TOOL_NAME = 'betterleaks'
export const TOOL_REPO_OWNER = 'betterleaks'
export const TOOL_REPO_NAME = 'betterleaks'

export const EXIT_CODE_CLEAN = 0
export const EXIT_CODE_LEAKS_FOUND = 1
export const EXIT_CODE_UNKNOWN_FLAG = 126

/**
 * Maps Node.js `${process.platform}-${process.arch}` to the release asset
 * suffix used by betterleaks. Asset filenames follow the pattern:
 *   betterleaks_{version}_{os}_{arch}.{tar.gz|zip}
 */
export const PLATFORM_MAP: Record<string, string> = {
  'linux-x64': 'linux_x64',
  'linux-arm64': 'linux_arm64',
  'darwin-x64': 'darwin_x64',
  'darwin-arm64': 'darwin_arm64',
  'win32-x64': 'windows_x64',
  'win32-arm64': 'windows_arm64'
}

export function getArchiveExtension(platform: string): string {
  return platform.startsWith('win32') ? 'zip' : 'tar.gz'
}

/**
 * Release asset filename, e.g. betterleaks_1.8.1_linux_x64.tar.gz. Must match
 * the second field of checksums.txt exactly for digest lookup to succeed.
 */
export function getAssetName(
  numericVersion: string,
  platform: string,
  arch: string
): string {
  const key = `${platform}-${arch}`
  const assetSuffix = PLATFORM_MAP[key]
  if (!assetSuffix) {
    throw new Error(`Unsupported platform/arch: ${key}`)
  }
  return `betterleaks_${numericVersion}_${assetSuffix}.${getArchiveExtension(platform)}`
}

export function getBinaryName(platform: string): string {
  return platform.startsWith('win32') ? 'betterleaks.exe' : 'betterleaks'
}
