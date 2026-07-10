import { X } from 'lucide-react';
import { useEffect } from 'react';

export default function Modal({ open, onClose, title, children, footer, size = 'md', bodyClassName = '', panelClassName = '', bodyRef }) {
  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);

  useEffect(() => {
    if (!open) return undefined;
    const root = document.documentElement;
    const previousRootOverflow = root.style.overflow;
    const previousRootScrollbarGutter = root.style.scrollbarGutter;
    const previousOverflow = document.body.style.overflow;
    root.style.overflow = 'hidden';
    root.style.scrollbarGutter = 'auto';
    document.body.style.overflow = 'hidden';
    return () => {
      root.style.overflow = previousRootOverflow;
      root.style.scrollbarGutter = previousRootScrollbarGutter;
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  if (!open) return null;

  const sizes = {
    sm: 'max-w-sm',
    md: 'max-w-md',
    lg: 'max-w-lg',
    xl: 'max-w-xl',
    '2xl': 'max-w-3xl',
    '3xl': 'max-w-4xl',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-graphite/45 backdrop-blur-sm"
         onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`bg-surface-card rounded-md border border-border shadow-2xl w-full ${sizes[size] || sizes.md} mx-4 max-h-[calc(100vh-2rem)] overflow-hidden flex flex-col ${panelClassName}`}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-border flex-shrink-0">
          <h3 className="text-base font-semibold text-text-primary">{title}</h3>
          <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded-md transition-colors">
            <X size={20} />
          </button>
        </div>
        <div ref={bodyRef} className={`min-h-0 flex-1 space-y-4 overflow-y-auto p-6 [scrollbar-gutter:stable] ${bodyClassName}`}>
          {children}
        </div>
        {footer && (
          <div className="flex justify-end gap-2 px-6 py-4 border-t border-border bg-surface-secondary flex-shrink-0">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
