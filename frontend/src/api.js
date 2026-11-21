export const formatDate = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai',
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function date(value) {
  return value ? formatDate.format(new Date(value)) : '—'
}

export async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
    options = { ...options, body: JSON.stringify(options.body) }
  }
  const response = await fetch(path, { ...options, headers })
  if (response.status === 204) return null
  let payload = null
  try {
    payload = await response.json()
  } catch {
    payload = null
  }
  if (!response.ok || (payload && payload.code && payload.code !== 'OK')) {
    const error = new Error(payload?.message || `请求失败（HTTP ${response.status}）`)
    error.status = response.status
    error.code = payload?.code
    throw error
  }
  return payload && 'data' in payload ? payload.data : payload
}
