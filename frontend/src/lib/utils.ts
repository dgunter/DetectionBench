import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Pair each item with a React key derived from its content. Identical items get
 * an occurrence suffix (`text`, `text#2`, …) so keys stay unique without
 * falling back to the array index.
 */
export function keyed<T>(items: readonly T[], keyOf: (item: T) => string): { key: string; item: T }[] {
  const seen = new Map<string, number>()
  return items.map((item) => {
    const base = keyOf(item)
    const n = (seen.get(base) ?? 0) + 1
    seen.set(base, n)
    return { key: n === 1 ? base : `${base}#${n}`, item }
  })
}
