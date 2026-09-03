import { Link } from "react-router-dom"
import { Button } from "@/components/ui/button"
import { api } from "@/lib/api"

export function Workbench({ onLoggedOut }: { onLoggedOut: () => void }) {
  async function logout() {
    await api.logout().catch(() => undefined)
    onLoggedOut()
  }
  return (
    <div className="flex min-h-svh flex-col">
      <header className="flex items-center justify-between border-b px-4 py-2">
        <div className="flex items-baseline gap-3">
          <span className="font-semibold">DetectionBench</span>
          <span className="text-xs text-muted-foreground">Sigma rule evaluation</span>
        </div>
        <nav className="flex items-center gap-2 text-sm">
          <Link to="/how-it-works" className="text-muted-foreground hover:underline">
            How this works
          </Link>
          <Button variant="ghost" size="sm" onClick={logout}>
            Log out
          </Button>
        </nav>
      </header>
      <main className="flex flex-1 items-center justify-center p-6 text-sm text-muted-foreground">
        Paste a Sigma rule to begin. (Pipeline wiring in progress.)
      </main>
    </div>
  )
}
