import { describe, expect, it } from "vitest"
import { resolveTheme, storedTheme } from "./theme"

describe("theme", () => {
  it("prefers a stored choice over the OS preference", () => {
    expect(resolveTheme("light", true)).toBe("light")
    expect(resolveTheme("dark", false)).toBe("dark")
  })
  it("falls back to the OS preference", () => {
    expect(resolveTheme(null, true)).toBe("dark")
    expect(resolveTheme(null, false)).toBe("light")
  })
  it("ignores garbage and storage errors", () => {
    expect(storedTheme(() => "purple")).toBeNull()
    expect(storedTheme(() => { throw new Error("blocked") })).toBeNull()
    expect(storedTheme(() => "dark")).toBe("dark")
  })
})
