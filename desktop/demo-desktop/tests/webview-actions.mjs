export function interactiveActionScript(id) {
  return actionScript(id, false)
}

export function activateActionScript(id) {
  return actionScript(id, true)
}

function actionScript(id, activate) {
  const activation = activate ? 'element.click()' : ''
  return `(() => {
    const element = document.getElementById(${JSON.stringify(id)})
    if (!(element instanceof HTMLButtonElement)
        || !element.isConnected
        || element.hidden
        || element.matches(':disabled')
        || element.getAttribute('aria-disabled') === 'true') {
      return false
    }
    for (let current = element;
         current instanceof Element;
         current = current.parentElement) {
      const style = window.getComputedStyle(current)
      if (style.display === 'none'
          || style.visibility === 'hidden'
          || style.visibility === 'collapse'
          || Number.parseFloat(style.opacity) === 0
          || style.pointerEvents === 'none'
          || (current instanceof HTMLElement && current.inert)) {
        return false
      }
    }
    const rectangle = element.getBoundingClientRect()
    const left = Math.max(rectangle.left, 0)
    const right = Math.min(rectangle.right, window.innerWidth)
    const top = Math.max(rectangle.top, 0)
    const bottom = Math.min(rectangle.bottom, window.innerHeight)
    if (right <= left || bottom <= top) {
      return false
    }
    const hit = document.elementFromPoint(
      (left + right) / 2,
      (top + bottom) / 2,
    )
    if (!(hit === element || element.contains(hit))) {
      return false
    }
    ${activation}
    return true
  })()`
}
