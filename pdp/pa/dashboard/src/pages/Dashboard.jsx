import { createElement, useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart as RechartsPieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Activity,
  PieChart as PieChartIcon,
} from 'lucide-react';
import {
  getAuditLog,
  getDashboardStats,
} from '../api';
import PageHeader from '../components/ui/PageHeader';

const CHART_COLORS = {
  accent: 'color-mix(in srgb, var(--color-accent) 68%, var(--color-white-smoke))',
  info: 'color-mix(in srgb, var(--color-info) 48%, var(--color-white-smoke))',
  success: '#9ed7aa',
  warning: '#f3d57b',
  danger: '#eba5a0',
  muted: 'color-mix(in srgb, var(--color-cool-steel) 54%, var(--color-white-smoke))',
  grid: 'color-mix(in srgb, var(--color-border-light) 70%, transparent)',
  text: 'var(--color-text-muted)',
};

const DECISION_PILL_STYLES = {
  Allowed: {
    background: 'color-mix(in srgb, #9ed7aa 42%, transparent)',
    color: '#2f6f3a',
  },
  'Step-up': {
    background: 'color-mix(in srgb, #f3d57b 48%, transparent)',
    color: '#79620a',
  },
  Blocked: {
    background: 'color-mix(in srgb, #eba5a0 46%, transparent)',
    color: '#93433d',
  },
  Failed: {
    background: 'color-mix(in srgb, #eba5a0 46%, transparent)',
    color: '#93433d',
  },
  Other: {
    background: 'color-mix(in srgb, var(--color-cool-steel) 26%, transparent)',
    color: 'var(--color-text-secondary)',
  },
};

const AXIS_STYLE = {
  fill: 'var(--color-text-muted)',
  fontSize: 12,
  fontWeight: 700,
};

const dashboardPanelClass = 'flex h-full flex-col rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.10)]';

function asList(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.value)) return data.value;
  return [];
}

function safeNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function formatNumber(value) {
  return new Intl.NumberFormat('ro-RO').format(safeNumber(value));
}

function normalizeText(value) {
  return String(value || '').trim().toLowerCase();
}

function classifyAuditEntry(entry) {
  const decision = normalizeText(entry?.decision);
  const type = normalizeText(entry?.event_type);
  const details = normalizeText(entry?.details);

  if (
    type.includes('disconnected') ||
    type.includes('revoked') ||
    type.includes('session_ended') ||
    type.includes('session_expired') ||
    decision.includes('ended') ||
    decision.includes('revoked') ||
    decision.includes('expired')
  ) {
    return 'Other';
  }
  if (decision.includes('deny') || type.includes('denied') || details.includes('denied')) {
    return 'Blocked';
  }
  if (decision.includes('step') || decision.includes('mfa') || type.includes('mfa')) {
    return 'Step-up';
  }
  if (decision.includes('allow') || entry?.success === true) {
    return 'Allowed';
  }
  if (entry?.success === false) {
    return 'Failed';
  }
  return 'Other';
}

function makeDecisionData(audit, stats) {
  const counts = new Map([
    ['Allowed', 0],
    ['Step-up', 0],
    ['Blocked', audit.length === 0 ? safeNumber(stats?.recent_denials) : 0],
    ['Failed', 0],
  ]);

  for (const entry of audit) {
    const label = classifyAuditEntry(entry);
    counts.set(label, (counts.get(label) || 0) + 1);
  }

  return [
    { label: 'Allowed', value: counts.get('Allowed') || 0, color: CHART_COLORS.success },
    { label: 'Step-up', value: counts.get('Step-up') || 0, color: CHART_COLORS.warning },
    { label: 'Blocked', value: counts.get('Blocked') || 0, color: CHART_COLORS.danger },
    { label: 'Failed', value: counts.get('Failed') || 0, color: CHART_COLORS.muted },
  ];
}

function makeActivityTrend(entries) {
  const days = [];
  const byDay = new Map();
  const start = new Date();
  start.setHours(0, 0, 0, 0);

  for (let index = 6; index >= 0; index -= 1) {
    const date = new Date(start);
    date.setDate(start.getDate() - index);
    const key = date.toISOString().slice(0, 10);
    const row = {
      key,
      label: date.toLocaleDateString('ro-RO', { day: '2-digit', month: 'short' }),
      allowed: 0,
      stepUp: 0,
      blocked: 0,
    };
    byDay.set(key, row);
    days.push(row);
  }

  for (const entry of entries) {
    const time = new Date(entry?.timestamp);
    if (Number.isNaN(time.getTime())) continue;
    const key = time.toISOString().slice(0, 10);
    const row = byDay.get(key);
    if (!row) continue;

    const label = classifyAuditEntry(entry);
    if (label === 'Allowed') row.allowed += 1;
    else if (label === 'Step-up') row.stepUp += 1;
    else if (label === 'Blocked' || label === 'Failed') row.blocked += 1;
  }

  return days;
}

function totalValue(data) {
  return data.reduce((sum, item) => sum + safeNumber(item.value), 0);
}

function DashboardPanel({ icon: Icon, title, right, children, className = '', bodyClassName = 'p-5' }) {
  return (
    <section className={`${dashboardPanelClass} ${className}`}>
      <div className="flex items-center justify-between gap-3 border-b border-[rgba(44,97,100,0.25)] px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          {createElement(Icon, { size: 18, className: 'shrink-0 text-accent' })}
          <h2 className="truncate text-base font-bold text-text-primary">{title}</h2>
        </div>
        {right}
      </div>
      <div className={`flex-1 ${bodyClassName}`}>{children}</div>
    </section>
  );
}

function DecisionPill({ label }) {
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide"
      style={DECISION_PILL_STYLES[label] || DECISION_PILL_STYLES.Other}
    >
      {label}
    </span>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;

  return (
    <div className="rounded-md border border-[rgba(44,97,100,0.55)] bg-surface-card px-3 py-2 shadow-[0_8px_16px_rgba(42,42,42,0.12)]">
      {label && <p className="mb-1 text-xs font-bold uppercase text-text-muted">{label}</p>}
      <div className="space-y-1">
        {payload.map((item) => (
          <div key={`${item.name}-${item.dataKey}`} className="flex items-center justify-between gap-4 text-sm">
            <span className="font-semibold text-text-secondary">{item.name || item.dataKey}</span>
            <span className="font-bold text-text-primary">{formatNumber(item.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChartLegend({ data }) {
  const total = totalValue(data);

  return (
    <div className="space-y-3">
      {data.map((item) => {
        const value = safeNumber(item.value);
        const percent = total > 0 ? Math.round((value / total) * 100) : 0;
        return (
          <div key={item.label} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4">
            <div className="flex min-w-0 items-center gap-2">
              <span className="h-3 w-3 shrink-0 rounded-sm" style={{ background: item.color }} />
              <span className="truncate text-sm font-semibold text-text-secondary">{item.label}</span>
            </div>
            <span className="text-right text-xs font-semibold text-text-muted">{percent}%</span>
          </div>
        );
      })}
    </div>
  );
}

function DonutChart({ data, centerLabel, centerValue, compact = false }) {
  const total = totalValue(data);
  const chartData = total > 0
    ? data.filter((item) => safeNumber(item.value) > 0)
    : [{ label: 'No data', value: 1, color: 'var(--color-border)' }];
  const chartSizeClass = compact ? 'h-[176px] max-w-[176px]' : 'h-[220px] max-w-[220px]';

  return (
    <div className="grid gap-4">
      <div className={`relative mx-auto w-full min-w-0 ${chartSizeClass}`}>
        <ResponsiveContainer width="100%" height="100%">
          <RechartsPieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="label"
              isAnimationActive={false}
              innerRadius={compact ? '66%' : '64%'}
              outerRadius={compact ? '88%' : '86%'}
              paddingAngle={2}
              stroke="var(--color-surface-card)"
              strokeWidth={4}
            >
              {chartData.map((item) => <Cell key={item.label} fill={item.color} />)}
            </Pie>
            {total > 0 && <Tooltip content={<ChartTooltip />} animationDuration={0} />}
          </RechartsPieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <div className={`${compact ? 'text-xl' : 'text-2xl'} font-bold leading-none text-text-primary`}>{formatNumber(centerValue ?? total)}</div>
            <div className="mt-1 text-xs font-bold uppercase text-text-muted">{centerLabel}</div>
          </div>
        </div>
      </div>
      <ChartLegend data={data} />
    </div>
  );
}

function ActivityAreaChart({ data, height = 260 }) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 12, right: 16, bottom: 0, left: -16 }}>
          <defs>
            <linearGradient id="allowedGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={CHART_COLORS.success} stopOpacity={0.28} />
              <stop offset="95%" stopColor={CHART_COLORS.success} stopOpacity={0.03} />
            </linearGradient>
            <linearGradient id="stepUpGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={CHART_COLORS.warning} stopOpacity={0.24} />
              <stop offset="95%" stopColor={CHART_COLORS.warning} stopOpacity={0.03} />
            </linearGradient>
            <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={CHART_COLORS.danger} stopOpacity={0.22} />
              <stop offset="95%" stopColor={CHART_COLORS.danger} stopOpacity={0.03} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="label" tick={AXIS_STYLE} tickLine={false} axisLine={false} height={24} />
          <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} allowDecimals={false} />
          <Area type="monotone" dataKey="allowed" name="Allowed" stroke={CHART_COLORS.success} fill="url(#allowedGradient)" strokeWidth={2} isAnimationActive={false} />
          <Area type="monotone" dataKey="stepUp" name="Step-up" stroke={CHART_COLORS.warning} fill="url(#stepUpGradient)" strokeWidth={2} isAnimationActive={false} />
          <Area type="monotone" dataKey="blocked" name="Blocked" stroke={CHART_COLORS.danger} fill="url(#blockedGradient)" strokeWidth={2} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function DashboardSkeleton() {
  const panels = [
    { className: 'xl:col-span-8', chartClassName: 'h-[280px]' },
    { className: 'xl:col-span-4', chartClassName: 'h-[280px]' },
  ];

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12" aria-label="Loading dashboard data">
      {panels.map((panel, index) => (
        <section
          key={panel.className}
          className={`${dashboardPanelClass} overflow-hidden ${panel.className}`}
        >
          <div className="flex items-center justify-between gap-3 border-b border-[rgba(44,97,100,0.25)] px-5 py-4">
            <div className="flex items-center gap-3">
              <div className="h-4 w-4 animate-pulse rounded bg-[rgba(44,97,100,0.18)]" />
              <div className="h-4 w-40 animate-pulse rounded bg-surface-hover" />
            </div>
            <div className="h-6 w-20 animate-pulse rounded-full bg-surface-hover" />
          </div>
          <div className="space-y-5 p-5">
            <div className={`grid place-items-center rounded-md border border-[rgba(44,97,100,0.35)] bg-[rgba(44,97,100,0.04)] ${panel.chartClassName}`}>
              <div className="h-28 w-28 animate-pulse rounded-full bg-surface-hover" />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              {[0, 1, 2].map((item) => (
                <div key={`${index}-${item}`} className="space-y-2">
                  <div className="h-3 w-24 animate-pulse rounded bg-surface-hover" />
                  <div className="h-4 w-full animate-pulse rounded bg-surface-hover" />
                </div>
              ))}
            </div>
          </div>
        </section>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState({});
  const [audit, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      setLoading(true);
      setError('');

      const results = await Promise.allSettled([
        getDashboardStats(),
        getAuditLog(40),
      ]);

      if (cancelled) return;

      const [statsResult, auditResult] = results;
      setStats(statsResult.status === 'fulfilled' && statsResult.value ? statsResult.value : {});
      setAudit(auditResult.status === 'fulfilled' ? asList(auditResult.value) : []);

      if (results.some((result) => result.status === 'rejected')) {
        setError('Some dashboard data could not be loaded.');
      }
      setLoading(false);
    }

    void loadDashboard();

    return () => {
      cancelled = true;
    };
  }, []);

  const decisionData = useMemo(() => makeDecisionData(audit, stats), [audit, stats]);
  const activityTrend = useMemo(() => makeActivityTrend(audit), [audit]);

  if (loading) {
    return (
      <>
        <PageHeader title="Security Dashboard" subtitle="Identity, access, device, and resource posture" />
        <DashboardSkeleton />
      </>
    );
  }

  return (
    <>
      <PageHeader title="Security Dashboard" subtitle="Identity, access, device, and resource posture" />

      {error && (
        <div className="mb-5 rounded-md border border-warning bg-warning-muted px-4 py-3 text-sm font-semibold text-warning">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <DashboardPanel
          icon={Activity}
          title="Access Activity"
          className="xl:col-span-8"
          bodyClassName="px-3 py-4 sm:px-5"
        >
          <ActivityAreaChart data={activityTrend} height={280} />
        </DashboardPanel>

        <DashboardPanel
          icon={PieChartIcon}
          title="Decisions"
          className="xl:col-span-4"
        >
          <DonutChart data={decisionData} centerLabel="Events" compact />
        </DashboardPanel>
      </div>
    </>
  );
}
