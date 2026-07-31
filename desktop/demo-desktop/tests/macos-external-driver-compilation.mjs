export function browserDriverCompilerArguments({
  output,
  productionTarget,
  source,
}) {
  return [
    'clang',
    '-target',
    productionTarget,
    '-dynamiclib',
    '-Wall',
    '-Werror',
    source,
    '-o',
    output,
  ]
}

export function webviewDriverCompilerArguments({
  output,
  productionTarget,
  source,
}) {
  return [
    'clang',
    '-target',
    productionTarget,
    '-dynamiclib',
    '-fobjc-arc',
    '-Wall',
    '-Werror',
    source,
    '-framework',
    'AppKit',
    '-framework',
    'Foundation',
    '-framework',
    'WebKit',
    '-o',
    output,
  ]
}
