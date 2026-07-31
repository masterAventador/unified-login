import { TauriDesktopAuthApi } from './api'
import { AuthController } from './app'
import { DomAuthView } from './view'
import './styles.css'

const view = new DomAuthView(document)
const controller = new AuthController(new TauriDesktopAuthApi(), view)

view.onLogin(() => {
  void controller.login()
})
view.onRetry(() => {
  void controller.initialize()
})
view.onLogout(() => {
  void controller.logout()
})

void controller.initialize()
