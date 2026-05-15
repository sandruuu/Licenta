import { Children, isValidElement, useEffect, useId, useMemo, useRef, useState } from 'react';
import { Check, ChevronDown } from 'lucide-react';

function optionText(children) {
  if (Array.isArray(children)) return children.map(optionText).join('');
  if (typeof children === 'string' || typeof children === 'number') return String(children);
  return '';
}

function optionsFromChildren(children) {
  return Children.toArray(children)
    .filter((child) => isValidElement(child) && child.type === 'option')
    .map((child) => ({
      value: child.props.value ?? optionText(child.props.children),
      label: child.props.children,
      text: optionText(child.props.children),
      disabled: !!child.props.disabled,
    }));
}

export default function SelectDropdown({
  value,
  defaultValue,
  onChange,
  children,
  className = '',
  menuClassName = '',
  disabled = false,
  name,
  placeholder = 'Select an option',
  buttonClassName = '',
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [internalValue, setInternalValue] = useState(defaultValue ?? '');
  const ref = useRef(null);
  const controlled = value !== undefined;
  const currentValue = controlled ? value : internalValue;
  const options = useMemo(() => optionsFromChildren(children), [children]);
  const selected = options.find((option) => String(option.value) === String(currentValue));

  useEffect(() => {
    if (!open) return undefined;
    const handlePointerDown = (event) => {
      if (ref.current && !ref.current.contains(event.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handlePointerDown);
    return () => document.removeEventListener('mousedown', handlePointerDown);
  }, [open]);

  const choose = (option) => {
    if (option.disabled) return;
    if (!controlled) setInternalValue(option.value);
    onChange?.({ target: { value: option.value, name } });
    setOpen(false);
  };

  const handleKeyDown = (event) => {
    if (disabled) return;
    if (event.key === 'Escape') {
      setOpen(false);
      return;
    }
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      setOpen((next) => !next);
    }
  };

  return (
    <div ref={ref} className={`relative ${className}`}>
      {name && <input type="hidden" name={name} value={currentValue ?? ''} />}
      <button
        id={id}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => !disabled && setOpen((next) => !next)}
        onKeyDown={handleKeyDown}
        className={`flex w-full items-center justify-between gap-3 border border-border bg-surface text-left font-bold text-text-primary shadow-sm transition-colors hover:border-text-muted focus:border-accent focus:outline-none focus:ring-[3px] focus:ring-accent-muted disabled:cursor-not-allowed disabled:opacity-50 ${buttonClassName}`}
      >
        <span className="min-w-0 truncate">
          {selected?.label || <span className="text-text-muted">{placeholder}</span>}
        </span>
        <ChevronDown size={16} className={`shrink-0 text-text-muted transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          role="listbox"
          aria-labelledby={id}
          className={`absolute left-0 z-40 mt-2 max-h-72 min-w-full overflow-hidden rounded-md border border-border bg-surface-card py-1 shadow-panel ${menuClassName}`}
        >
          <div className="max-h-72 overflow-y-auto p-1">
            {options.map((option) => {
              const active = String(option.value) === String(currentValue);
              return (
                <button
                  key={`${option.value}-${option.text}`}
                  type="button"
                  role="option"
                  aria-selected={active}
                  disabled={option.disabled}
                  onClick={() => choose(option)}
                  className={`flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-sm font-semibold transition-colors ${
                    active
                      ? 'bg-accent-muted text-text-primary'
                      : 'text-text-secondary hover:bg-surface-hover hover:text-text-primary'
                  } disabled:cursor-not-allowed disabled:opacity-45`}
                >
                  <span className="min-w-0 truncate">{option.label}</span>
                  <span className={`grid h-4 w-4 shrink-0 place-items-center rounded-sm border ${
                    active ? 'border-accent bg-accent text-white-smoke' : 'border-border bg-surface'
                  }`}>
                    {active && <Check size={12} />}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
