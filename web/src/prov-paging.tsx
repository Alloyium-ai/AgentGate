// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Client-side pages over a bounded API list. The provisioning list endpoints
// return at most a fixed number of newest records and no cursor; the pager
// says so instead of implying the list is complete.

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
