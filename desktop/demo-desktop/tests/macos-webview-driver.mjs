import { createConnection } from 'node:net'

export function createWebViewDriver({ port, token }) {
  async function evaluate(script) {
    const response = await request(port, { token, script })
    return responseValue(response)
  }

  async function terminate() {
    const response = await request(port, { token, command: 'terminate' })
    responseValue(response)
  }

  return { evaluate, terminate }
}

function responseValue(response) {
  if (response.ok !== true) {
    throw new Error(`WebView 测试探针执行失败: ${response.error}`)
  }
  return response.value
}

function request(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port })
    let response = ''

    socket.setEncoding('utf8')
    socket.setTimeout(20_000, () => {
      socket.destroy(new Error('WebView 测试探针响应超时'))
    })
    socket.once('error', reject)
    socket.on('data', (chunk) => {
      response += chunk
      const newline = response.indexOf('\n')
      if (newline === -1) {
        return
      }
      socket.end()
      try {
        resolve(JSON.parse(response.slice(0, newline)))
      } catch (error) {
        reject(error)
      }
    })
    socket.once('connect', () => {
      socket.write(`${JSON.stringify(payload)}\n`)
    })
  })
}
