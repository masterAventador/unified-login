const PLATFORM_TEST =
  'tests/acceptance-unit-platform.node-test.mjs'
const PORTABLE_TESTS = [
  PLATFORM_TEST,
  'tests/bundle-configuration.node-test.mjs',
  'tests/acceptance-auth-server.node-test.mjs',
  'tests/acceptance-environment.node-test.mjs',
  'tests/acceptance-http.node-test.mjs',
  'tests/acceptance-java.node-test.mjs',
  'tests/acceptance-oauth.node-test.mjs',
  'tests/acceptance-workspace.node-test.mjs',
  'tests/macos-external-driver-compilation.node-test.mjs',
  'tests/production-artifact-path.node-test.mjs',
  'tests/sdk-delegation.node-test.mjs',
]
const MACOS_TESTS = [
  'tests/acceptance-processes.node-test.mjs',
  'tests/browser-opener-interceptor.node-test.mjs',
  'tests/macos-application-launch.node-test.mjs',
  'tests/macos-webview-driver.node-test.mjs',
]

export function acceptanceUnitTestFiles(platform) {
  return platform === 'darwin'
    ? [...PORTABLE_TESTS, ...MACOS_TESTS]
    : PORTABLE_TESTS
}
