export async function responseIsOkWithin(
  url,
  timeout,
  fetchImplementation = fetch,
) {
  try {
    const response = await fetchImplementation(url, {
      signal: AbortSignal.timeout(timeout),
    })
    return response.ok
  } catch {
    return false
  }
}
