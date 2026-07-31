import { createTauriAuthClient } from './api'
import { AuthController } from './app'
import { DomAuthView } from './view'
import './styles.css'

const view = new DomAuthView(document)
const controller = new AuthController(createTauriAuthClient(), view)

view.onLogin(() => {
  void controller.login()
})
view.onRetry(() => {
  void controller.retry()
})
view.onLogout(() => {
  void controller.logout()
})

void controller.initialize()

setInterval(() => {
  void controller.maintain()
}, 15_000)
