// Thin same-origin API client. Cookies carry the session; nothing secret lives here.

import type { ClassifyResponse } from "./types"
import type { CandidatesResult, ExplainResult, ModelKey, SuggestAttackResult } from "./llm"

export class ApiError extends Error {
  status: number
  code?: string
  constructor(status: number, message: string, code?: string) {
    super(message)
    this.status = status
    this.code = code
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
    let code: string | undefined
    try {
      const body = await res.json()
      if (typeof body?.detail === "string") detail = body.detail
      if (typeof body?.error?.code === "string") code = body.error.code
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail, code)
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
  llmBudget: () => request<{ remaining: number; limit: number }>("/api/llm/budget"),
  llmExplain: (rule: string, model: ModelKey) =>
    request<ExplainResult>("/api/llm/explain", { method: "POST", body: JSON.stringify({ rule, model }) }),
  llmSuggestAttack: (rule: string, model: ModelKey) =>
    request<SuggestAttackResult>("/api/llm/suggest-attack", { method: "POST", body: JSON.stringify({ rule, model }) }),
  llmCandidates: (rule: string, model: ModelKey) =>
    request<CandidatesResult>("/api/llm/candidates", { method: "POST", body: JSON.stringify({ rule, model }) }),
  session: () => request<{ authenticated: boolean }>("/api/auth/session"),
  verifyToken: (token: string) =>
    request<void>("/api/auth/verify", { method: "POST", body: JSON.stringify({ token }) }),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),
  classify: (rule: string) =>
    request<ClassifyResponse>("/api/classify", { method: "POST", body: JSON.stringify({ rule }) }),
  health: () =>
    request<{ status: string; version: string; pysigma_version: string; attack_dataset_version: string }>(
      "/api/health",
    ),
}
