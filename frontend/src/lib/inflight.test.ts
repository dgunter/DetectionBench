import { describe, expect, it } from "vitest"
import { RequestGuard, isAbortError } from "./inflight"

describe("RequestGuard", () => {
  it("marks a request stale and aborts it when a newer one begins", () => {
    const guard = new RequestGuard()
    const first = guard.begin()
    expect(first.isCurrent()).toBe(true)
    expect(first.signal.aborted).toBe(false)

    const second = guard.begin()
    expect(first.isCurrent()).toBe(false)
    expect(first.signal.aborted).toBe(true)
    expect(second.isCurrent()).toBe(true)
    expect(second.signal.aborted).toBe(false)
  })

  it("cancel aborts the in-flight request and leaves nothing current", () => {
    const guard = new RequestGuard()
    const req = guard.begin()
    guard.cancel()
    expect(req.isCurrent()).toBe(false)
    expect(req.signal.aborted).toBe(true)
    guard.cancel() // idempotent with nothing in flight
    expect(guard.begin().isCurrent()).toBe(true)
  })
})

describe("isAbortError", () => {
  it("recognises only fetch's AbortError", () => {
    expect(isAbortError(new DOMException("aborted", "AbortError"))).toBe(true)
    expect(isAbortError(new DOMException("x", "NotFoundError"))).toBe(false)
    expect(isAbortError(new Error("AbortError"))).toBe(false)
  })
})
