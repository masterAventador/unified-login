import WebAuthClient from '@unified-login/web'

import { AdminApi } from './api'
import { AdminApplication } from './app'
import { createAdminRuntimeConfig } from './config'
import { AdminDomView } from './view'
import './styles.css'

const root = document.querySelector<HTMLElement>('#app')

if (root === null) {
  throw new Error('管理后台缺少应用根节点')
}

const runtimeConfig = createAdminRuntimeConfig(
  import.meta.env.VITE_AUTH_SERVER_URL ?? 'http://localhost:9000',
  window.location.origin,
)
const auth = new WebAuthClient({
  issuer: runtimeConfig.authServer,
  clientId: 'admin-web',
  redirectUri: runtimeConfig.redirectUri,
})

const application = new AdminApplication(
  auth,
  new AdminApi(runtimeConfig.authServer),
  new AdminDomView(document, root),
)

void application.start()
