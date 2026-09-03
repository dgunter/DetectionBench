// Thin same-origin API client. Cookies carry the session; nothing secret lives here.

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      if (typeof body?.detail === "string") detail = body.detail
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export interface Example {
  id: string
  label: string
  blurb: string
  title: string
  yaml: string
}

export const api = {
  examples: () => request<Example[]>("/api/examples"),
  session: () => request<{ authenticated: boolean }>("/api/auth/session"),
  verifyToken: (token: string) =>
    request<void>("/api/auth/verify", { method: "POST", body: JSON.stringify({ token }) }),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),
  health: () =>
    request<{ status: string; version: string; pysigma_version: string; attack_dataset_version: string }>(
      "/api/health",
    ),
}
