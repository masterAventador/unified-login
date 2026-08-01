import assert from 'node:assert/strict'
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

const TAURI_DIRECTORY = 'src-tauri'
const REQUIRED_BUNDLE_ICONS = [
  'icons/32x32.png',
  'icons/128x128.png',
  'icons/128x128@2x.png',
  'icons/icon.icns',
  'icons/icon.ico',
]

test('最终桌面包显式声明各平台图标且资源文件真实存在', () => {
  const configuration = JSON.parse(
    readFileSync(join(TAURI_DIRECTORY, 'tauri.conf.json'), 'utf8'),
  )

  assert.deepEqual(configuration.bundle.icon, REQUIRED_BUNDLE_ICONS)
  for (const icon of REQUIRED_BUNDLE_ICONS) {
    assert.ok(
      statSync(join(TAURI_DIRECTORY, icon)).isFile(),
      `缺少桌面包图标：${icon}`,
    )
  }
})

test('Windows MSI 使用能编码中文产品名的本地化语言', () => {
  const configuration = JSON.parse(
    readFileSync(join(TAURI_DIRECTORY, 'tauri.conf.json'), 'utf8'),
  )

  assert.equal(configuration.bundle.windows?.wix?.language, 'zh-CN')
})
