export interface AdminRuntimeConfig {
  readonly authServer: string
  readonly redirectUri: string
}

export function createAdminRuntimeConfig(
  configuredAuthServer: string,
  pageOrigin: string,
): AdminRuntimeConfig {
  const authServer = parseHttpUrl(configuredAuthServer, '认证中心地址无效')
  if (
    authServer.pathname !== '/'
    || authServer.search !== ''
    || authServer.hash !== ''
  ) {
    throw new Error('认证中心地址不能包含路径、查询参数或片段')
  }

  const adminOrigin = parseHttpUrl(pageOrigin, '管理后台地址无效')
  return {
    authServer: authServer.origin,
    redirectUri: new URL('/callback', adminOrigin.origin).toString(),
  }
}

function parseHttpUrl(value: string, errorMessage: string): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error(errorMessage)
  }
  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:')
    || url.username !== ''
    || url.password !== ''
  ) {
    throw new Error(errorMessage)
  }
  return url
}
