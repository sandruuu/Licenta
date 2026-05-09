import { useState, useRef, useEffect } from 'react';

export default function DropdownMenu({ trigger, items, align = 'right' }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const alignClass = align === 'right' ? 'right-0' : 'left-0';

  return (
    <div ref={ref} className="relative inline-block">
      <div onClick={() => setOpen(!open)}>{trigger}</div>
      {open && (
        <div className={`absolute ${alignClass} mt-2 w-56 bg-surface-card rounded-md shadow-lg border border-border py-1 z-20`}>
          {items.map((item, i) => (
            item.separator ? (
              <div key={i} className="border-t border-border my-1" />
            ) : (
              <button
                key={i}
                onClick={() => { item.onClick(); setOpen(false); }}
                className="w-full text-left px-4 py-2 text-sm text-text-secondary hover:bg-surface-hover flex items-center gap-2 transition-colors"
              >
                {item.icon && <item.icon size={16} className={item.iconClass || ''} />}
                {item.label}
              </button>
            )
          ))}
        </div>
      )}
    </div>
  );
}
