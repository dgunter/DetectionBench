// Pure helpers for the access flow, kept free of React so they can be unit-tested.

/** Extract the token from a shareable link's query string, or null. */
export function tokenFromSearch(search: string): string | null {
  const token = new URLSearchParams(search).get("token")
  return token && token.trim().length > 0 ? token.trim() : null
}

/** Where to send the user after the shareable link is consumed: always "/" with the token stripped. */
export function postAccessRedirect(): string {
  return "/"
}

export function describeAuthError(status: number, fallback: string): string {
  if (status === 401) return "That access token isn't valid."
  if (status === 429) return "Too many attempts. Wait a minute and try again."
  if (status === 503) return "The access gate isn't configured on this server yet."
  return fallback || "Something went wrong."
}
