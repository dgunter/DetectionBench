import { describe, expect, it } from "vitest"
import { keyed } from "./utils"

describe("keyed", () => {
  it("uses the content key when items are unique", () => {
    expect(keyed(["a", "b"], (s) => s).map((k) => k.key)).toEqual(["a", "b"])
  })

  it("suffixes repeated content so keys stay unique and stable", () => {
    const out = keyed(["AND", "x", "AND", "AND"], (s) => s)
    expect(out.map((k) => k.key)).toEqual(["AND", "x", "AND#2", "AND#3"])
    expect(out.map((k) => k.item)).toEqual(["AND", "x", "AND", "AND"])
  })
})
