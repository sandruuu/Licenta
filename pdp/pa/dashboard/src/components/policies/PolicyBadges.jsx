import Badge from '../ui/Badge';
import { actionIcons, layerIcons } from './policyIcons';
import { actionMeta, conditionSummary, layerMeta } from './policyModel';

export function ActionBadge({ action }) {
  const meta = actionMeta(action);
  const Icon = actionIcons[action] || actionIcons.allow;
  return (
    <Badge variant={meta.variant} className="gap-1">
      <Icon size={12} />
      {meta.short}
    </Badge>
  );
}

export function LayerBadge({ level }) {
  const meta = layerMeta(level);
  const Icon = layerIcons[level] || layerIcons.organization;
  return (
    <Badge variant={level === 'resource_group' ? 'accent' : 'neutral'} className="gap-1">
      <Icon size={12} />
      {meta.shortLabel}
    </Badge>
  );
}

export function PolicySentence({ policy }) {
  const conditions = conditionSummary(policy);
  return (
    <div className="text-[12px] leading-6 text-text-secondary">
      <span className="font-semibold text-text-primary">IF</span>{' '}
      {conditions.map((condition, index) => (
        <span key={`${condition}-${index}`}>
          {index > 0 && <span className="font-semibold text-text-primary"> AND </span>}
          {condition}
        </span>
      ))}{' '}
      <span className="font-semibold text-text-primary">THEN</span>{' '}
      <span className="font-semibold text-accent">{actionMeta(policy.action).label}</span>
    </div>
  );
}
