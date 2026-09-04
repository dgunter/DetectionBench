import { useState, type SubmitEvent } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { ApiError, api } from "@/lib/api"
import { describeAuthError } from "@/lib/session"

export function AccessGate({ onAuthenticated }: Readonly<{ onAuthenticated: () => void }>) {
  const [token, setToken] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: SubmitEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!token.trim() || busy) return
    setBusy(true)
    setError(null)
    try {
      await api.verifyToken(token.trim())
      onAuthenticated()
    } catch (err) {
      setError(err instanceof ApiError ? describeAuthError(err.status, err.message) : "Network error.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="flex min-h-svh items-center justify-center bg-muted/40 p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <img src="/logo.png" alt="" className="size-7" />
            <span>DetectionBench</span>
          </CardTitle>
          <CardDescription>Enter your access token to continue.</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <Input
              type="password"
              autoComplete="off"
              placeholder="Access token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-label="Access token"
              autoFocus
            />
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={busy || !token.trim()}>
              {busy ? "Checking…" : "Continue"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}
