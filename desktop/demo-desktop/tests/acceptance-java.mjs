import { join } from 'node:path'

export function javaExecutable(environment) {
  const javaHome = environment.JAVA_HOME
  if (typeof javaHome === 'string' && javaHome.trim() !== '') {
    return join(javaHome, 'bin', 'java')
  }
  return 'java'
}
