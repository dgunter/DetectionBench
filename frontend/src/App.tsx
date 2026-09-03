import { useCallback, useEffect, useState } from "react"
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"
import { AccessGate } from "@/pages/AccessGate"
import { AccessLink } from "@/pages/AccessLink"
import { HowItWorks } from "@/pages/HowItWorks"
import { Workbench } from "@/pages/Workbench"
import { api } from "@/lib/api"

type AuthState = "checking" | "anonymous" | "authenticated"

export default function App() {
  const [auth, setAuth] = useState<AuthState>("checking")

  useEffect(() => {
    api
      .session()
      .then((s) => setAuth(s.authenticated ? "authenticated" : "anonymous"))
      .catch(() => setAuth("anonymous"))
  }, [])

  const onAuthenticated = useCallback(() => setAuth("authenticated"), [])
  const onLoggedOut = useCallback(() => setAuth("anonymous"), [])

  if (auth === "checking") {
    return <div className="flex min-h-svh items-center justify-center text-sm text-muted-foreground">Loading…</div>
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/access" element={<AccessLink onAuthenticated={onAuthenticated} />} />
        <Route
          path="/how-it-works"
          element={auth === "authenticated" ? <HowItWorks /> : <Navigate to="/" replace />}
        />
        <Route
          path="/"
          element={
            auth === "authenticated" ? (
              <Workbench onLoggedOut={onLoggedOut} />
            ) : (
              <AccessGate onAuthenticated={onAuthenticated} />
            )
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
