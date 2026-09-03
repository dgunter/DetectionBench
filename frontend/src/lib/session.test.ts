import { describe, expect, it } from "vitest"
import { describeAuthError, postAccessRedirect, tokenFromSearch } from "./session"

describe("tokenFromSearch", () => {
  it("reads the token", () => {
    expect(tokenFromSearch("?token=abc123")).toBe("abc123")
  })
  it("ignores empty or missing tokens", () => {
    expect(tokenFromSearch("?token=")).toBeNull()
    expect(tokenFromSearch("?other=1")).toBeNull()
    expect(tokenFromSearch("")).toBeNull()
  })
})

describe("access redirect", () => {
  it("never carries the token forward", () => {
    expect(postAccessRedirect()).toBe("/")
  })
})

describe("describeAuthError", () => {
  it("maps statuses to friendly copy", () => {
    expect(describeAuthError(401, "")).toMatch(/isn't valid/)
    expect(describeAuthError(429, "")).toMatch(/Too many/)
    expect(describeAuthError(500, "boom")).toBe("boom")
  })
})
