import { Plus } from 'lucide-react';

export default function PageHeader({ title, subtitle, createLabel, onCreate, size = 'large' }) {
  const isLarge = size === 'large';

  return (
    <div className="mb-4 border-b border-border pb-4 pr-3 pt-1">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className={`${isLarge ? 'text-[28px]' : 'text-[22px]'} font-bold leading-tight text-text-primary`}>{title}</h1>
          {subtitle && <p className={`mt-1 ${isLarge ? 'text-base' : 'text-sm'} font-semibold text-text-secondary`}>{subtitle}</p>}
        </div>
        {createLabel && onCreate && (
          <button
            type="button"
            onClick={onCreate}
            className="inline-flex shrink-0 items-center gap-2 rounded-md bg-accent px-5 py-2.5 text-sm font-bold text-white-smoke shadow-accent transition-colors hover:bg-accent-hover sm:mt-2"
          >
            <Plus size={16} />
            {createLabel}
          </button>
        )}
      </div>
    </div>
  );
}
