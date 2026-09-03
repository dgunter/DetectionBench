import { Link } from "react-router-dom"

export function HowItWorks() {
  return (
    <main className="mx-auto max-w-3xl p-6">
      <Link to="/" className="text-sm text-muted-foreground underline">
        ← Back to DetectionBench
      </Link>
      <h1 className="mt-4 text-2xl font-semibold">How this works</h1>
      <p className="mt-2 text-muted-foreground">Coming shortly.</p>
    </main>
  )
}
