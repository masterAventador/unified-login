import { isAbsolute, join } from 'node:path'

const RUST_TARGET_PATTERN = /^[A-Za-z0-9_.-]+$/

export function macosProductionArtifact(
  metadataOutput,
  bundleName,
  productionTarget,
) {
  const metadata = JSON.parse(metadataOutput)
  const targetDirectory = metadata.target_directory
  if (
    typeof targetDirectory !== 'string'
    || !isAbsolute(targetDirectory)
  ) {
    throw new Error('Cargo metadata 没有返回绝对目标目录')
  }
  if (
    typeof productionTarget !== 'string'
    || !RUST_TARGET_PATTERN.test(productionTarget)
  ) {
    throw new Error('生产目标三元组无效')
  }
  return join(
    targetDirectory,
    productionTarget,
    'release',
    'bundle',
    'macos',
    bundleName,
  )
}

export function rustHostTarget(versionOutput) {
  const hostTarget = /^host:\s*(\S+)\s*$/m.exec(versionOutput)?.[1]
  if (
    hostTarget === undefined
    || !RUST_TARGET_PATTERN.test(hostTarget)
  ) {
    throw new Error('rustc 没有返回本机目标')
  }
  return hostTarget
}
