import { createElement, useEffect, useMemo, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
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
  AlertTriangle,
  Clock3,
  FileText,
  KeyRound,
  Monitor,
  PieChart as PieChartIcon,
  Radio,
  Server,
  ShieldCheck,
} from 'lucide-react';
import {
  getAuditLog,
  getDashboardStats,
  getDeviceDataReports,
  getResources,
  getSessions,
} from '../api';
import Badge from '../components/ui/Badge';
import PageHeader from '../components/ui/PageHeader';
import { formatDateTime } from '../utils/format';

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

const RESOURCE_TYPE_CHART_COLORS = {
  web: '#1f6f78',
  ssh: '#4353a3',
  rdp: '#7550a8',
};

const TONE_STYLES = {
  accent: {
    background: 'color-mix(in srgb, var(--color-accent) 14%, transparent)',
    color: 'var(--color-accent)',
  },
  info: {
    background: 'color-mix(in srgb, var(--color-info) 13%, transparent)',
    color: 'var(--color-info)',
  },
  success: {
    background: 'color-mix(in srgb, #9ed7aa 34%, transparent)',
    color: '#2f6f3a',
  },
  warning: {
    background: 'color-mix(in srgb, #f3d57b 42%, transparent)',
    color: '#79620a',
  },
  danger: {
    background: 'color-mix(in srgb, #eba5a0 36%, transparent)',
    color: '#93433d',
  },
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

function devicePosture(report) {
  const checks = asList(report?.checks);
  if (checks.length === 0) return 'No data';
  if (checks.some((check) => normalizeText(check.status) === 'critical')) return 'Critical';
  if (checks.some((check) => ['warning', 'unavailable'].includes(normalizeText(check.status)))) return 'Warning';
  return 'Healthy';
}

function getResourceType(resource) {
  return resource?.type || resource?.protocol || 'other';
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

function makeDeviceData(reports, stats) {
  if (reports.length === 0) {
    const totalDevices = safeNumber(stats?.total_devices);
    const healthyDevices = safeNumber(stats?.healthy_devices);
    return [
      { label: 'Healthy', value: healthyDevices, color: CHART_COLORS.success },
      { label: 'Needs attention', value: Math.max(totalDevices - healthyDevices, 0), color: CHART_COLORS.warning },
      { label: 'No data', value: 0, color: CHART_COLORS.muted },
    ];
  }

  const counts = new Map([
    ['Healthy', 0],
    ['Warning', 0],
    ['Critical', 0],
    ['No data', 0],
  ]);

  for (const report of reports) {
    const posture = devicePosture(report);
    counts.set(posture, (counts.get(posture) || 0) + 1);
  }

  return [
    { label: 'Healthy', value: counts.get('Healthy') || 0, color: CHART_COLORS.success },
    { label: 'Warning', value: counts.get('Warning') || 0, color: CHART_COLORS.warning },
    { label: 'Critical', value: counts.get('Critical') || 0, color: CHART_COLORS.danger },
    { label: 'No data', value: counts.get('No data') || 0, color: CHART_COLORS.muted },
  ];
}

function makeResourceTypeData(resources) {
  const counts = new Map();
  for (const resource of resources) {
    const type = getResourceType(resource);
    counts.set(type, (counts.get(type) || 0) + 1);
  }

  const palette = [CHART_COLORS.accent, CHART_COLORS.info, CHART_COLORS.success, CHART_COLORS.warning, CHART_COLORS.muted];
  const entries = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  if (entries.length === 0) {
    return [{ label: 'No resources', value: 0, color: CHART_COLORS.muted }];
  }

  return entries.map(([label, value], index) => ({
    label,
    value,
    color: RESOURCE_TYPE_CHART_COLORS[String(label || '').toLowerCase()] || palette[index % palette.length],
  }));
}

function makeSessionData(sessions, stats) {
  const now = Date.now();
  const active = sessions.filter((session) => {
    const expires = new Date(session?.expires_at).getTime();
    return !session?.revoked && (!Number.isFinite(expires) || expires > now);
  }).length;
  const revoked = sessions.filter((session) => session?.revoked).length;
  const expired = Math.max(sessions.length - active - revoked, 0);

  return [
    { label: 'Active', value: sessions.length ? active : safeNumber(stats?.active_sessions), color: CHART_COLORS.success },
    { label: 'Expired', value: expired, color: CHART_COLORS.muted },
    { label: 'Revoked', value: revoked, color: CHART_COLORS.danger },
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

function MetricCard({ icon: Icon, label, value, detail, tone = 'accent' }) {
  return (
    <div className="rounded-md border border-border bg-surface-card p-4 shadow-surface transition-colors hover:border-accent">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-bold uppercase text-text-muted">{label}</p>
          <p className="mt-3 text-3xl font-bold leading-none text-text-primary">{formatNumber(value)}</p>
        </div>
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md" style={TONE_STYLES[tone] || TONE_STYLES.accent}>
          {createElement(Icon, { size: 20 })}
        </div>
      </div>
      {detail && <p className="mt-3 truncate text-sm font-semibold text-text-secondary">{detail}</p>}
    </div>
  );
}

function DashboardPanel({ icon: Icon, title, right, children, className = '', bodyClassName = 'p-5' }) {
  return (
    <section className={`flex h-full flex-col rounded-md border border-border bg-surface-card shadow-surface ${className}`}>
      <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-accent-muted text-accent">
            {createElement(Icon, { size: 18 })}
          </div>
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
    <div className="rounded-md border border-border bg-surface-card px-3 py-2 shadow-panel">
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
          <div key={item.label} className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2">
              <span className="h-3 w-3 shrink-0 rounded-sm" style={{ background: item.color }} />
              <span className="truncate text-sm font-semibold text-text-secondary">{item.label}</span>
            </div>
            <div className="shrink-0 text-right">
              <span className="text-sm font-bold text-text-primary">{formatNumber(value)}</span>
              <span className="ml-2 text-xs font-semibold text-text-muted">{percent}%</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DonutChart({ data, centerLabel, centerValue, compact = false, sideLegend = false }) {
  const total = totalValue(data);
  const chartData = total > 0
    ? data.filter((item) => safeNumber(item.value) > 0)
    : [{ label: 'No data', value: 1, color: 'var(--color-border)' }];
  const layoutClass = sideLegend
    ? 'grid gap-5 sm:grid-cols-[176px_1fr] sm:items-center'
    : compact
      ? 'grid gap-4'
      : 'grid gap-5 md:grid-cols-[220px_1fr] md:items-center';

  return (
    <div className={layoutClass}>
      <div className={`relative min-w-0 ${compact || sideLegend ? 'h-[176px]' : 'h-[220px]'}`}>
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

function VerticalBarChart({ data, height = 260, barSize = 34 }) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 12, right: 12, bottom: 2, left: -16 }}>
          <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="label" tick={AXIS_STYLE} tickLine={false} axisLine={false} interval={0} />
          <YAxis tick={AXIS_STYLE} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--color-accent-muted)' }} animationDuration={0} />
          <Bar dataKey="value" name="Events" radius={[6, 6, 0, 0]} barSize={barSize} isAnimationActive={false}>
            {data.map((item) => <Cell key={item.label} fill={item.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function HorizontalBarChart({ data, height = 240, axisWidth = 118 }) {
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 16, bottom: 8, left: 16 }}>
          <CartesianGrid stroke={CHART_COLORS.grid} strokeDasharray="3 3" horizontal={false} />
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="label"
            tick={AXIS_STYLE}
            tickLine={false}
            axisLine={false}
            width={axisWidth}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--color-accent-muted)' }} animationDuration={0} />
          <Bar dataKey="value" name="Count" radius={[0, 6, 6, 0]} barSize={16} isAnimationActive={false}>
            {data.map((item) => <Cell key={item.label} fill={item.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
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

function ActivityFeed({ entries }) {
  if (entries.length === 0) {
    return (
      <div className="grid place-items-center rounded-md border border-dashed border-border p-10 text-center">
        <FileText size={36} className="mb-3 text-text-muted" />
        <p className="text-sm font-bold text-text-primary">No audit events</p>
      </div>
    );
  }

  return (
    <div className="divide-y divide-border-light">
      {entries.map((entry, index) => {
        const label = classifyAuditEntry(entry);
        return (
          <div key={entry.id || `${entry.timestamp}-${index}`} className="grid gap-3 py-4 first:pt-0 last:pb-0 lg:grid-cols-[1fr_150px_120px] lg:items-center">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <DecisionPill label={label} />
                <span className="truncate text-sm font-bold text-text-primary">{entry.event_type || 'event'}</span>
              </div>
              <p className="mt-1 truncate text-sm font-semibold text-text-secondary">
                {entry.username || 'system'}{entry.resource ? ` -> ${entry.resource}` : ''}
              </p>
            </div>
            <span className="text-mono text-xs text-text-muted">{entry.source_ip || '-'}</span>
            <span className="text-mono text-xs text-text-muted lg:text-right">{formatDateTime(entry.timestamp)}</span>
          </div>
        );
      })}
    </div>
  );
}

function DashboardSkeleton() {
  const panels = [
    { className: 'xl:col-span-8', chartClassName: 'h-[280px]' },
    { className: 'xl:col-span-4', chartClassName: 'h-[280px]' },
    { className: 'xl:col-span-12', chartClassName: 'h-[220px]' },
  ];

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-12" aria-label="Loading dashboard data">
      {panels.map((panel, index) => (
        <section
          key={panel.className}
          className={`overflow-hidden rounded-md border border-border bg-surface-card shadow-surface ${panel.className}`}
        >
          <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
            <div className="flex items-center gap-3">
              <div className="h-9 w-9 animate-pulse rounded-md bg-surface-hover" />
              <div className="h-4 w-40 animate-pulse rounded bg-surface-hover" />
            </div>
            <div className="h-6 w-20 animate-pulse rounded-full bg-surface-hover" />
          </div>
          <div className="space-y-5 p-5">
            <div className={`grid place-items-center rounded-md bg-surface-hover/50 ${panel.chartClassName}`}>
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
  const [resources, setResources] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [deviceReports, setDeviceReports] = useState([]);
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
        getResources(),
        getSessions(),
        getDeviceDataReports(),
      ]);

      if (cancelled) return;

      const [statsResult, auditResult, resourcesResult, sessionsResult, deviceReportsResult] = results;
      setStats(statsResult.status === 'fulfilled' && statsResult.value ? statsResult.value : {});
      setAudit(auditResult.status === 'fulfilled' ? asList(auditResult.value) : []);
      setResources(resourcesResult.status === 'fulfilled' ? asList(resourcesResult.value) : []);
      setSessions(sessionsResult.status === 'fulfilled' ? asList(sessionsResult.value) : []);
      setDeviceReports(deviceReportsResult.status === 'fulfilled' ? asList(deviceReportsResult.value) : []);

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
  const deviceData = useMemo(() => makeDeviceData(deviceReports, stats), [deviceReports, stats]);
  const resourceTypeData = useMemo(() => makeResourceTypeData(resources), [resources]);
  const sessionData = useMemo(() => makeSessionData(sessions, stats), [sessions, stats]);
  const activityTrend = useMemo(() => makeActivityTrend(audit), [audit]);

  const getDecisionValue = (label) => safeNumber(decisionData.find((item) => item.label === label)?.value);
  const loadedDecisionEvents = totalValue(decisionData);
  const allowedEvents = getDecisionValue('Allowed');
  const stepUpEvents = getDecisionValue('Step-up');
  const blockedEvents = getDecisionValue('Blocked') + getDecisionValue('Failed');
  const allowedRate = loadedDecisionEvents > 0 ? Math.round((allowedEvents / loadedDecisionEvents) * 100) : 0;
  const totalDevices = deviceReports.length || safeNumber(stats?.total_devices);
  const recentDenials = safeNumber(stats?.recent_denials);
  const mfaSignals = audit.filter((entry) => classifyAuditEntry(entry) === 'Step-up').length;

  const riskData = [
    { label: 'Recent denials', value: recentDenials, color: CHART_COLORS.danger },
    { label: 'MFA step-ups', value: mfaSignals, color: CHART_COLORS.warning },
    { label: 'Unhealthy devices', value: Math.max(totalDevices - safeNumber(stats?.healthy_devices), 0), color: CHART_COLORS.muted },
  ];

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

      <div className="mb-5 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard icon={Activity} label="Access events" value={loadedDecisionEvents} detail={`${formatNumber(audit.length)} audit entries loaded`} tone="accent" />
        <MetricCard icon={ShieldCheck} label="Allowed" value={allowedEvents} detail={`${allowedRate}% of decisions`} tone="success" />
        <MetricCard icon={KeyRound} label="Step-up" value={stepUpEvents} detail="MFA challenges required" tone="warning" />
        <MetricCard icon={AlertTriangle} label="Blocked" value={blockedEvents} detail={`${formatNumber(recentDenials)} recent denials`} tone={blockedEvents > 0 ? 'danger' : 'warning'} />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        <DashboardPanel
          icon={Activity}
          title="Access Activity"
          right={<Badge variant="info">7 days</Badge>}
          className="xl:col-span-8"
          bodyClassName="px-3 py-4 sm:px-5"
        >
          <ActivityAreaChart data={activityTrend} height={280} />
        </DashboardPanel>

        <DashboardPanel
          icon={PieChartIcon}
          title="Decision Mix"
          right={<Badge variant="accent">Last {formatNumber(audit.length)}</Badge>}
          className="xl:col-span-4"
        >
          <DonutChart data={decisionData} centerLabel="Events" compact sideLegend />
        </DashboardPanel>

        <DashboardPanel icon={Monitor} title="Device Posture" right={<Badge variant={safeNumber(stats?.healthy_devices) === totalDevices ? 'success' : 'warning'}>{formatNumber(totalDevices)} devices</Badge>} className="xl:col-span-3">
          <DonutChart data={deviceData} centerLabel="Devices" centerValue={totalDevices} compact />
        </DashboardPanel>

        <DashboardPanel icon={ShieldCheck} title="Risk Signals" className="xl:col-span-3">
          <HorizontalBarChart data={riskData} height={210} axisWidth={116} />
        </DashboardPanel>

        <DashboardPanel icon={Server} title="Resource Types" className="xl:col-span-3">
          <VerticalBarChart data={resourceTypeData} height={210} barSize={28} />
        </DashboardPanel>

        <DashboardPanel icon={Radio} title="Session State" right={<Badge variant="info">{formatNumber(totalValue(sessionData))} total</Badge>} className="xl:col-span-3">
          <DonutChart data={sessionData} centerLabel="Sessions" compact />
        </DashboardPanel>

        <DashboardPanel
          icon={Clock3}
          title="Recent Security Activity"
          className="xl:col-span-12"
        >
          <ActivityFeed entries={audit.slice(0, 8)} />
        </DashboardPanel>
      </div>
    </>
  );
}
