import { createHash } from 'node:crypto'

export function acceptanceCredentialService(processId, runId) {
  if (!Number.isInteger(processId) || processId <= 1) {
    throw new Error('桌面验收进程 PID 无效')
  }
  if (typeof runId !== 'string' || runId.length === 0) {
    throw new Error('桌面验收轮次标识无效')
  }
  return `com.aventador.unified-login.acceptance.${processId}.${runId}`
}

export function credentialAccount(baseAccount, issuer, clientId) {
  const canonicalIssuer = new URL(issuer)
  if (!canonicalIssuer.pathname.endsWith('/')) {
    canonicalIssuer.pathname += '/'
  }
  const digest = createHash('sha256')
    .update(canonicalIssuer.toString())
    .update('\0')
    .update(clientId)
    .digest('base64url')
  return `${baseAccount}:${digest}`
}

export function acceptanceSignalConfigurations() {
  return [
    { exitCode: 129, signal: 'SIGHUP' },
    { exitCode: 130, signal: 'SIGINT' },
    { exitCode: 143, signal: 'SIGTERM' },
  ]
}

export function productionAppEnvironment(environment, overrides) {
  const applicationEnvironment = { ...environment }
  for (const name of Object.keys(applicationEnvironment)) {
    if (
      name === 'DYLD_INSERT_LIBRARIES'
      || name.startsWith('UNIFIED_LOGIN_')
    ) {
      delete applicationEnvironment[name]
    }
  }
  return {
    ...applicationEnvironment,
    ...overrides,
  }
}

export function authServerEnvironment(environment, overrides) {
  const serverEnvironment = { ...environment }
  for (const name of Object.keys(serverEnvironment)) {
    if (authServerConfigurationVariable(name)) {
      delete serverEnvironment[name]
    }
  }
  return {
    ...serverEnvironment,
    ...overrides,
  }
}

function authServerConfigurationVariable(name) {
  const normalizedName = name
    .toUpperCase()
    .replaceAll('.', '_')
    .replaceAll('-', '_')
  return (
    normalizedName.startsWith('SPRING_')
    || normalizedName.startsWith('SERVER_')
    || normalizedName.startsWith('UNIFIED_LOGIN_')
    || [
      'ADMIN_WEB_REDIRECT_URI',
      'BOOTSTRAP_ADMIN_EMAILS',
      'DB_PASSWORD',
      'DB_URL',
      'DB_USERNAME',
      'ISSUER_URL',
      'JAVA_TOOL_OPTIONS',
      'JDK_JAVA_OPTIONS',
      'JAVA_OPTS',
      'JWT_KEY_STORE',
      '_JAVA_OPTIONS',
    ].includes(normalizedName)
  )
}
