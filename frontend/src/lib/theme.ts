// Light/dark theme: a class on <html>, remembered per browser, defaulting to the OS preference.

export type Theme = "light" | "dark"

const KEY = "db-theme"

export function storedTheme(read: (k: string) => string | null): Theme | null {
  try {
    const v = read(KEY)
    return v === "light" || v === "dark" ? v : null
  } catch {
    return null
  }
}

export function resolveTheme(stored: Theme | null, prefersDark: boolean): Theme {
  return stored ?? (prefersDark ? "dark" : "light")
}

export function currentTheme(): Theme {
  return document.documentElement.classList.contains("dark") ? "dark" : "light"
}

export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark")
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    /* storage unavailable: the choice lasts for this page only */
  }
}
