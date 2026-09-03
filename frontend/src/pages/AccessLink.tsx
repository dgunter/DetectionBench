import { useEffect, useState } from "react"
import { useLocation, useNavigate } from "react-router-dom"
import { ApiError, api } from "@/lib/api"
import { describeAuthError, postAccessRedirect, tokenFromSearch } from "@/lib/session"

/** /access?token=… — submit once, set the cookie, land on / with the token gone from the URL. */
export function AccessLink({ onAuthenticated }: { onAuthenticated: () => void }) {
  const { search } = useLocation()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const token = tokenFromSearch(search)
    if (!token) {
      navigate(postAccessRedirect(), { replace: true })
      return
    }
    let cancelled = false
    api
      .verifyToken(token)
      .then(() => {
        if (cancelled) return
        onAuthenticated()
        navigate(postAccessRedirect(), { replace: true })
      })
      .catch((err) => {
        if (cancelled) return
        setError(err instanceof ApiError ? describeAuthError(err.status, err.message) : "Network error.")
      })
    return () => {
      cancelled = true
    }
  }, [search, navigate, onAuthenticated])

  return (
    <main className="flex min-h-svh items-center justify-center p-6 text-sm text-muted-foreground">
      {error ? (
        <p role="alert" className="text-destructive">
          {error} <a className="underline" href="/">Enter a token manually.</a>
        </p>
      ) : (
        <p>Signing you in…</p>
      )}
    </main>
  )
}
