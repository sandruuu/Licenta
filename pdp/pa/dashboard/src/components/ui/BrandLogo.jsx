import { Shield } from 'lucide-react';

export default function BrandLogo({
  className = 'inline-flex items-center gap-3',
  iconBoxClassName = 'grid h-10 w-10 shrink-0 place-items-center text-accent',
  iconClassName = 'h-7 w-7',
  textWrapperClassName = '',
  titleClassName = 'text-lg font-bold leading-none text-text-primary',
}) {
  return (
    <div className={className}>
      <span className={iconBoxClassName}>
        <Shield className={iconClassName} />
      </span>
      <div className={textWrapperClassName}>
        <h1 className={titleClassName}>
          <span className="text-accent">TRUST</span>Cloud
        </h1>
      </div>
    </div>
  );
}
