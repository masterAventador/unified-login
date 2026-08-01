const PROXY_VARIABLES = [
  'ALL_PROXY',
  'all_proxy',
  'HTTP_PROXY',
  'http_proxy',
  'HTTPS_PROXY',
  'https_proxy',
]

export function createDemoApiProcessPlan({
  environment,
}) {
  const runtimeEnvironment = { ...environment }
  for (const variable of PROXY_VARIABLES) {
    runtimeEnvironment[variable] = ''
  }
  runtimeEnvironment.NO_PROXY = 'localhost,127.0.0.1'
  runtimeEnvironment.no_proxy = 'localhost,127.0.0.1'

  return [
    {
      command: 'uv',
      arguments: ['sync', '--locked'],
      environment: { ...environment },
    },
    {
      command: 'uv',
      arguments: [
        'run',
        '--locked',
        '--no-sync',
        'uvicorn',
        'demo_api.app:app',
        '--host',
        '127.0.0.1',
        '--port',
        '8000',
      ],
      environment: runtimeEnvironment,
    },
  ]
}
