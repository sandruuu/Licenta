import { useMemo, useState } from 'react';

export const TABLE_PAGE_SIZE = 6;

export function usePaginatedTable(items, pageSize = TABLE_PAGE_SIZE) {
  const [currentPage, setCurrentPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil((items?.length || 0) / pageSize));
  const safeCurrentPage = Math.min(Math.max(currentPage, 1), totalPages);

  const pageItems = useMemo(() => {
    const start = (safeCurrentPage - 1) * pageSize;
    return (items || []).slice(start, start + pageSize);
  }, [items, pageSize, safeCurrentPage]);

  return {
    currentPage: safeCurrentPage,
    pageItems,
    pageSize,
    resetPage: () => setCurrentPage(1),
    setCurrentPage,
    totalPages,
  };
}
