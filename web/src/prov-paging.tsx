// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Pages over provisioning lists. Targets, profiles and secrets return at most
// a fixed number of newest records and are paged in the browser (the pager
// says when the bound applies); launches are paged by the service with a
// cursor.

import React, { useEffect, useState } from "react";
import { ChevronRight } from "lucide-react";

export function useClientPages<T>(items: T[], size = 25) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(items.length / size));
  useEffect(() => {
    if (page > pages - 1) setPage(0);
  }, [pages, page]);
  const current = Math.min(page, pages - 1);
  return { items: items.slice(current * size, current * size + size), page: current, pages, total: items.length, setPage };
}

export function ClientPager({ page, pages, total, setPage, bound }: { page: number; pages: number; total: number; setPage: (n: number) => void; bound?: number }) {
  if (total === 0) return null;
  return (
    <nav className="pager" aria-label="Pages">
      <button className="secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>
        Previous
      </button>
      <span>
        Page {page + 1} of {pages} · {total} records{bound && total >= bound ? ` (the API returns the newest ${bound})` : ""}
      </span>
      <button className="secondary" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>
        Next <ChevronRight size={14} aria-hidden="true" />
      </button>
    </nav>
  );
}

// useCursorPages pages a list endpoint that answers next_cursor: it keeps the
// cursor of every page it visited, so Previous returns to exactly that page.
// Changing the filters (the key) starts again at the first page.
export function useCursorPages(key: string) {
  const [state, setState] = useState<{ key: string; cursors: string[] }>({ key, cursors: [""] });
  const cursors = state.key === key ? state.cursors : [""];
  const page = cursors.length - 1;
  return {
    cursor: cursors[page],
    page,
    next: (cursor: string) => setState({ key, cursors: [...cursors, cursor] }),
    previous: () => setState({ key, cursors: cursors.length > 1 ? cursors.slice(0, -1) : cursors }),
  };
}

export function CursorPager({ page, size, shown, next, onNext, onPrevious }: { page: number; size: number; shown: number; next?: string; onNext: (c: string) => void; onPrevious: () => void }) {
  if (page === 0 && !next) return null;
  return (
    <nav className="pager" aria-label="Pages">
      <button className="secondary" disabled={page === 0} onClick={onPrevious}>
        Previous
      </button>
      <span>
        Page {page + 1} · {shown} of at most {size} per page{next ? "" : " · last page"}
      </span>
      <button className="secondary" disabled={!next} onClick={() => next && onNext(next)}>
        Next <ChevronRight size={14} aria-hidden="true" />
      </button>
    </nav>
  );
}
