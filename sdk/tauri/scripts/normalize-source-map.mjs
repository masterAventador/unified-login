import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export function normalizeSourceMap(sourceMap) {
  if (!Array.isArray(sourceMap.sourcesContent)) {
    throw new Error('SDK source map 缺少 sourcesContent')
  }
  return {
    ...sourceMap,
    sourcesContent: sourceMap.sourcesContent.map((source) => (
      typeof source === 'string' ? source.replace(/\r\n?/g, '\n') : source
    )),
  }
}

async function normalizeBuiltSourceMap() {
  const sourceMapUrl = new URL('../dist/index.js.map', import.meta.url)
  const sourceMap = JSON.parse(await readFile(sourceMapUrl, 'utf8'))
  await writeFile(sourceMapUrl, JSON.stringify(normalizeSourceMap(sourceMap)))
}

if (
  process.argv[1] !== undefined
  && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  await normalizeBuiltSourceMap()
}
