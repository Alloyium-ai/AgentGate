// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Compares an answer of the browser QA's API fixture with answers the real
// service gave (web/qa/fixtures/api, recorded by
// internal/control/web_fixtures_test.go). The fixture may not invent a field
// the service never sends, may not give a field another JSON type, and must
// send every field the service always sends. A field the service sends only
// sometimes (it is missing from one of several real samples) is optional; a
// path listed in `optional` may be present or absent (a field the service
// sends only in states the recorded samples do not reach); a path in `maps` is an object with free keys
// (extra_headers, counts); a path in `skip` is not compared (a launch spec
// the service echoes is the client's own input). `null` matches any type, as
// Go writes a nil list.

const kind = (v) => (v === null || v === undefined ? "null" : Array.isArray(v) ? "array" : typeof v);

export function shapeIssues(mock, samples, { optional = [], maps = [], skip = [], required = true } = {}) {
  const issues = [];
  const opt = new Set(optional);
  const free = new Set(maps);
  const skipped = new Set(skip);
  const walk = (value, reals, path) => {
    if (skipped.has(path)) return;
    reals = reals.filter((r) => kind(r) !== "null");
    if (kind(value) === "null" || !reals.length) return;
    const kinds = new Set(reals.map(kind));
    if (!kinds.has(kind(value))) {
      issues.push(`${path || "(answer)"}: the fixture sends ${kind(value)}, the service ${[...kinds].join(" or ")}`);
      return;
    }
    if (kind(value) === "array") {
      const elems = reals.filter((r) => kind(r) === "array").flat();
      for (const v of value) walk(v, elems, path + "[]");
      return;
    }
    if (kind(value) !== "object") return;
    const objs = reals.filter((r) => kind(r) === "object");
    if (free.has(path)) {
      const vals = objs.flatMap((o) => Object.values(o));
      for (const v of Object.values(value)) walk(v, vals, path + ".*");
      return;
    }
    const known = new Set(objs.flatMap((o) => Object.keys(o)));
    for (const k of Object.keys(value)) {
      if (!known.has(k) && opt.has(`${path}.${k}`)) continue;
      if (!known.has(k)) issues.push(`${path}.${k}: the service never sends this field`);
      else walk(value[k], objs.map((o) => o[k]), `${path}.${k}`);
    }
    if (!required) return;
    for (const k of known) {
      if (k in value || opt.has(`${path}.${k}`)) continue;
      if (objs.every((o) => k in o)) issues.push(`${path}.${k}: the service always sends this field; the fixture does not`);
    }
  };
  walk(mock, samples, "");
  return issues;
}
