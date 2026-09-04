// Bookkeeping for one in-flight request at a time: the newest request is the
// only one whose result may be shown, and superseding it aborts the old fetch.

export interface InFlight {
  /** Pass to fetch so superseding this request cancels it on the wire. */
  signal: AbortSignal
  /** True while this is still the newest request; false once superseded or cancelled. */
  isCurrent: () => boolean
}

export class RequestGuard {
  private generation = 0
  private controller: AbortController | null = null

  /** Supersede whatever is in flight and start a new request. */
  begin(): InFlight {
    this.cancel()
    const gen = ++this.generation
    const controller = new AbortController()
    this.controller = controller
    return { signal: controller.signal, isCurrent: () => gen === this.generation }
  }

  /** Abort the in-flight request, if any, and mark it stale. */
  cancel(): void {
    this.controller?.abort()
    this.controller = null
    this.generation++
  }
}

/** True for the error fetch throws when its signal is aborted. */
export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError"
}
