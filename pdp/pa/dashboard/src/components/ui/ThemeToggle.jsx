import { useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { getCurrentTheme, saveTheme } from '../../theme';

export default function ThemeToggle({
  borderless = false,
  className = '',
  collapsibleLabel = false,
  labelClassName = '',
  showLabel = false,
}) {
  const [theme, setTheme] = useState(() => getCurrentTheme());
  const nextLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  const displayLabel = theme === 'dark' ? 'Light mode' : 'Dark mode';
  const Icon = theme === 'dark' ? Sun : Moon;

  const toggle = () => {
    setTheme((current) => saveTheme(current === 'dark' ? 'light' : 'dark'));
  };

  return (
    <button
      type="button"
      title={nextLabel}
      aria-label={nextLabel}
      onClick={toggle}
      className={`flex shrink-0 items-center rounded-md text-text-secondary transition-colors hover:bg-accent-muted hover:text-accent ${
        borderless ? 'bg-transparent' : 'border border-border bg-surface hover:border-accent'
      } ${
        showLabel ? `h-11 w-full px-3 text-sm font-bold ${collapsibleLabel ? 'gap-0' : 'gap-3'}` : 'h-9 w-9 justify-center'
      } ${className}`}
    >
      <Icon size={16} />
      {showLabel && (
        <span className={`min-w-0 overflow-hidden whitespace-nowrap transition-all duration-200 ${labelClassName}`}>
          {displayLabel}
        </span>
      )}
    </button>
  );
}
