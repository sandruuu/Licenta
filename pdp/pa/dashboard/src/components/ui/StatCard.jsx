import { createElement } from 'react';

const iconColors = {
  blue:    'bg-info-muted text-info',
  green:   'bg-success-muted text-success',
  orange:  'bg-warning-muted text-warning',
  red:     'bg-danger-muted text-danger',
  purple:  'bg-accent-muted text-accent',
};

export default function StatCard({ label, value, icon, color = 'blue' }) {
  return (
    <div className="bg-surface-card border border-border rounded-md p-4 transition-all duration-200
                    hover:border-accent animate-[cardFadeIn_0.35s_ease-out_both]">
      <div className="flex justify-between items-center mb-3">
        <span className="text-[10px] text-text-muted uppercase tracking-[0.8px] font-bold">{label}</span>
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${iconColors[color] || iconColors.blue}`}>
          {icon ? createElement(icon, { className: 'w-[18px] h-[18px]' }) : null}
        </div>
      </div>
      <div className="text-[22px] font-bold tracking-[-0.5px] leading-none">{value}</div>
    </div>
  );
}
