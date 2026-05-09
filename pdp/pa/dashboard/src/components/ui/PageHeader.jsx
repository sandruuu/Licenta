import { Plus } from 'lucide-react';

export default function PageHeader({ title, subtitle, createLabel, onCreate }) {
  return (
    <div className="flex items-center justify-between mb-7">
      <div>
        <h2 className="text-[18px] font-bold tracking-[-0.3px] text-text-primary">{title}</h2>
        {subtitle && <p className="text-xs text-text-secondary mt-0.5 font-medium">{subtitle}</p>}
      </div>
      {createLabel && onCreate && (
        <button
          onClick={onCreate}
          className="inline-flex items-center gap-1.5 px-4 py-2 bg-accent text-white rounded-md
                     hover:bg-accent-hover transition-colors font-semibold text-xs shadow-sm"
        >
          <Plus size={16} />
          {createLabel}
        </button>
      )}
    </div>
  );
}
