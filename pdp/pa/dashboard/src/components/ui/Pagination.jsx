import { ChevronLeft, ChevronRight } from 'lucide-react';

function pageItems(currentPage, totalPages) {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  if (currentPage <= 4) {
    return [1, 2, 3, 4, 5, 'end-ellipsis', totalPages];
  }

  if (currentPage >= totalPages - 3) {
    return [1, 'start-ellipsis', totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
  }

  return [1, 'start-ellipsis', currentPage - 1, currentPage, currentPage + 1, 'end-ellipsis', totalPages];
}

export default function Pagination({ currentPage, totalPages, onPageChange }) {
  const safeTotalPages = Math.max(1, totalPages || 1);
  const safeCurrentPage = Math.min(Math.max(currentPage || 1, 1), safeTotalPages);

  const goToPage = (page) => {
    const nextPage = Math.min(Math.max(page, 1), safeTotalPages);
    if (nextPage !== safeCurrentPage) onPageChange(nextPage);
  };

  return (
    <nav className="flex items-center justify-center gap-3" aria-label="Pagination">
      <button
        type="button"
        onClick={() => goToPage(safeCurrentPage - 1)}
        disabled={safeCurrentPage === 1}
        className="flex h-10 w-10 items-center justify-center rounded-full bg-surface-card text-text-secondary shadow-surface transition-colors hover:bg-surface-hover hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-45"
        aria-label="Previous page"
      >
        <ChevronLeft size={18} />
      </button>

      <div className="flex items-center gap-1 rounded-full bg-surface-card px-3 py-1.5 shadow-surface">
        {pageItems(safeCurrentPage, safeTotalPages).map((item) => {
          if (typeof item === 'string') {
            return (
              <span key={item} className="flex h-8 min-w-8 items-center justify-center px-1 text-sm font-semibold text-text-muted">
                ...
              </span>
            );
          }

          const active = item === safeCurrentPage;
          return (
            <button
              key={item}
              type="button"
              onClick={() => goToPage(item)}
              className={`flex h-8 min-w-8 items-center justify-center rounded-md px-2 text-sm font-semibold transition-colors ${
                active
                  ? 'bg-accent text-white-smoke'
                  : 'text-text-secondary hover:bg-surface-hover hover:text-text-primary'
              }`}
              aria-current={active ? 'page' : undefined}
            >
              {item}
            </button>
          );
        })}
      </div>

      <button
        type="button"
        onClick={() => goToPage(safeCurrentPage + 1)}
        disabled={safeCurrentPage === safeTotalPages}
        className="flex h-10 w-10 items-center justify-center rounded-full bg-surface-card text-text-secondary shadow-surface transition-colors hover:bg-surface-hover hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-45"
        aria-label="Next page"
      >
        <ChevronRight size={18} />
      </button>
    </nav>
  );
}
