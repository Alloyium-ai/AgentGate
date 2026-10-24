// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Follows one launch's events. It reads GET /api/v1/launches/{id}/events as
// Server-Sent Events, resumes after the last sequence it holds (?after= and
// Last-Event-ID), reconnects with capped exponential backoff, and falls back
// to polling the same endpoint as JSON when the stream keeps failing. The
// service ends every stream after five minutes; that is a normal reconnect.

export type SSEMessage = { id?: string; event: string; data: string };

// SSEParser implements the text/event-stream line format (WHATWG HTML
// 9.2.6) for the fields this API sends: event, data and id.
export class SSEParser {
  private buffer = "";
  private data: string[] = [];
  private event = "";
  private id?: string;
  push(chunk: string): SSEMessage[] {
    this.buffer += chunk;
    const out: SSEMessage[] = [];
    const lines = this.buffer.split(/\r\n|\r|\n/);
    this.buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (line === "") {
        if (this.data.length) out.push({ id: this.id, event: this.event || "message", data: this.data.join("\n") });
        this.data = [];
        this.event = "";
        continue;
      }
      if (line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? "" : line.slice(colon + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "data") this.data.push(value);
      else if (field === "event") this.event = value;
      else if (field === "id" && !value.includes("\0")) this.id = value;
    }
    return out;
  }
}

export type StreamEvent = { seq: number; kind: string; [key: string]: unknown };
export type StreamStatus = {
  mode: "connecting" | "live" | "reconnecting" | "polling" | "stopped";
  attempt: number;
  lastSeq: number;
  detail?: string;
};
export type StreamOptions = {
  after?: number;
  onEvent: (event: StreamEvent) => void;
  onStatus?: (status: StreamStatus) => void;
  onSessionEnded?: () => void;
  fetchImpl?: typeof fetch;
  pollMs?: number;
  maxBackoffMs?: number;
  failuresBeforePoll?: number;
  sseRetryWhilePollingMs?: number;
  base?: string;
};

export function backoff(attempt: number, max = 30000) {
  return Math.min(max, 1000 * 2 ** Math.max(0, attempt - 1));
}

export function followLaunch(id: string, options: StreamOptions): { stop: () => void } {
  const doFetch = options.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const base = options.base ?? "/api/v1";
  const pollMs = options.pollMs ?? 5000;
  const failuresBeforePoll = options.failuresBeforePoll ?? 4;
  let lastSeq = options.after ?? 0;
  let attempt = 0;
  let failures = 0;
  let stopped = false;
  let controller: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;
  let polling = false;
  const status = (mode: StreamStatus["mode"], detail?: string) => options.onStatus?.({ mode, attempt, lastSeq, detail });
  const deliver = (raw: Record<string, unknown>, id?: string) => {
    const seq = Number(raw.seq ?? id);
    if (!Number.isInteger(seq) || seq <= lastSeq) return;
    lastSeq = seq;
    options.onEvent({ ...raw, seq, kind: String(raw.kind ?? "") });
  };
  const ended = (res: Response) => {
    if (res.status === 401) {
      stopped = true;
      status("stopped", "Your session ended. Sign in again to follow this launch.");
      options.onSessionEnded?.();
      return true;
    }
    return false;
  };
  const schedule = () => {
    if (stopped) return;
    if (failures >= failuresBeforePoll) {
      startPolling();
      timer = setTimeout(connect, options.sseRetryWhilePollingMs ?? 60000);
      return;
    }
    status("reconnecting");
    timer = setTimeout(connect, backoff(attempt, options.maxBackoffMs));
  };
  const startPolling = () => {
    if (polling || stopped) return;
    polling = true;
    status("polling", `Live updates are unavailable; checking every ${Math.round(pollMs / 1000)} s.`);
    const tick = async () => {
      if (stopped || !polling) return;
      try {
        const res = await doFetch(`${base}/launches/${encodeURIComponent(id)}/events?after=${lastSeq}&limit=200`, { credentials: "same-origin", headers: { Accept: "application/json" } });
        if (ended(res)) return;
        if (res.ok) {
          const body = (await res.json()) as { items?: Record<string, unknown>[] };
          for (const item of body.items || []) deliver(item);
        }
      } catch {
        /* the next tick retries */
      }
      if (!stopped && polling) pollTimer = setTimeout(tick, pollMs);
    };
    tick();
  };
  let live = false;
  const connect = async () => {
    if (stopped) return;
    attempt++;
    // A planned reconnect after a normal end keeps the live status.
    if (!live) status(attempt > 1 ? "reconnecting" : "connecting");
    controller = new AbortController();
    let ready = false;
    try {
      const res = await doFetch(`${base}/launches/${encodeURIComponent(id)}/events?after=${lastSeq}`, {
        credentials: "same-origin",
        headers: { Accept: "text/event-stream", "Last-Event-ID": String(lastSeq) },
        signal: controller.signal,
      });
      if (ended(res)) return;
      if (!res.ok || !res.body || !(res.headers.get("Content-Type") || "").includes("text/event-stream")) throw new Error(`stream refused (${res.status})`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      const parser = new SSEParser();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        for (const message of parser.push(decoder.decode(value, { stream: true }))) {
          if (message.event === "ready") {
            ready = true;
            live = true;
            attempt = 0;
            failures = 0;
            if (polling) {
              polling = false;
              clearTimeout(pollTimer);
            }
            clearTimeout(timer);
            status("live");
            continue;
          }
          try {
            deliver(JSON.parse(message.data), message.id);
          } catch {
            /* a malformed event is skipped; the sequence resumes it */
          }
        }
      }
      if (!ready) throw new Error("stream ended before it was ready");
      // A normal end (the service closes streams after five minutes).
      if (!stopped) timer = setTimeout(connect, 1000);
      return;
    } catch (error) {
      if (stopped || controller.signal.aborted) return;
      live = false;
      failures++;
      status("reconnecting", error instanceof Error ? error.message : undefined);
    }
    schedule();
  };
  connect();
  return {
    stop() {
      stopped = true;
      polling = false;
      clearTimeout(timer);
      clearTimeout(pollTimer);
      controller?.abort();
      status("stopped");
    },
  };
}
