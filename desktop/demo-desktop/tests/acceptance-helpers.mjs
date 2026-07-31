export function loopbackPortFromLsof(output) {
  const ports = output
    .split(/\r?\n/)
    .map((line) => /^n127\.0\.0\.1:(\d+)$/.exec(line)?.[1])
    .filter((value) => value !== undefined)
    .map(Number)
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65_535)

  if (ports.length !== 1) {
    throw new Error('桌面进程必须恰好有一个 IPv4 回环监听端口')
  }
  return ports[0]
}

export function validateBrowserLoginUrl(value) {
  const normalized = value.startsWith('localhost:9000/')
    ? `http://${value}`
    : value
  const url = new URL(normalized)
  if (url.origin !== 'http://localhost:9000' || url.pathname !== '/login') {
    throw new Error('系统默认浏览器没有停在预期的认证中心登录页')
  }
}

export function containsPlaintextSecret(content, secret) {
  return secret.length > 0 && content.indexOf(secret) !== -1
}

export function parseBrowserProbe(output) {
  const [bundleId, url, ...extra] = output.trim().split(/\r?\n/)
  const supported = new Set([
    'com.apple.Safari',
    'com.brave.Browser',
    'com.google.Chrome',
    'com.microsoft.edgemac',
    'company.thebrowser.Browser',
    'org.mozilla.firefox',
  ])
  if (
    bundleId === undefined ||
    url === undefined ||
    extra.length > 0 ||
    !supported.has(bundleId)
  ) {
    throw new Error('系统调起的前台应用不是受支持的系统浏览器')
  }
  return { bundleId, url }
}
