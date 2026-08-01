import assert from 'node:assert/strict'
import { join } from 'node:path'
import { test } from 'node:test'

import { javaExecutable } from './acceptance-java.mjs'

test('认证中心复用 Maven 通过 JAVA_HOME 选择的 Java', () => {
  const javaHome = join('test-fixtures', 'jdk-17')
  assert.equal(
    javaExecutable({
      JAVA_HOME: javaHome,
      PATH: join('external', 'java-8', 'bin'),
    }),
    join(javaHome, 'bin', 'java'),
  )
})

test('没有 JAVA_HOME 时通过 PATH 解析 Java', () => {
  assert.equal(
    javaExecutable({ PATH: join('test-fixtures', 'jdk-17', 'bin') }),
    'java',
  )
  assert.equal(javaExecutable({ JAVA_HOME: '   ' }), 'java')
})
