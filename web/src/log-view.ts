// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Agent output is untrusted. These helpers keep it as text: control
// characters and bidirectional overrides become visible escapes, the buffer
// is bounded, and nothing is ever parsed as markup. React renders the result
// as text nodes only.

export type Line = { seq: number; time: string; stream: string; text: string };

export const TRUNCATION_MARKER = "[output truncated at the 1 MiB launch log limit]";

// visible replaces characters that could hide or reorder text (C0 controls
// except tab and newline, DEL, C1 controls, and Unicode bidi controls) with
// visible escapes such as \x1b and ‮.
export function visible(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g, (c) => {
    const code = c.charCodeAt(0);
    return code < 0x100 ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

export class LogBuffer {
  lines: Line[] = [];
  dropped = 0;
  constructor(public max = 20000) {}
  get lastSeq() {
    return this.lines.at(-1)?.seq ?? 0;
  }
  append(items: Line[]): number {
    let added = 0;
    for (const item of items) {
      if (item.seq <= this.lastSeq) continue;
      this.lines.push({ ...item, text: String(item.text ?? "") });
      added++;
    }
    if (this.lines.length > this.max) {
      this.dropped += this.lines.length - this.max;
      this.lines = this.lines.slice(-this.max);
    }
    return added;
  }
  hasMarker() {
    return this.lines.some((l) => l.text.includes(TRUNCATION_MARKER));
  }
}

export function filterLines(lines: Line[], query: string): Line[] {
  const q = query.trim().toLowerCase();
  if (!q) return lines;
  return lines.filter((l) => l.text.toLowerCase().includes(q) || l.stream.toLowerCase() === q);
}

// toText is the download form: one line per record, escapes kept, so a
// downloaded file shows exactly what the page showed.
export function toText(lines: Line[]): string {
  return lines.map((l) => `${l.time} ${l.stream} ${visible(l.text)}`).join("\n") + (lines.length ? "\n" : "");
}
