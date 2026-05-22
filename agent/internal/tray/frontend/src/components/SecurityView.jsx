import { useMemo, useState } from 'react';
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle,
  ChevronRight,
  ExternalLink,
  Flame,
  HardDrive,
  HelpCircle,
  Laptop,
  Loader2,
  Lock,
  Monitor,
  RefreshCw,
  Shield,
} from 'lucide-react';
import {
  formatDateTime,
  formatStatusLabel,
  normalizeStatus,
} from '../lib/dashboard';

const CHECKS = [
  {
    id: 'os',
    names: ['operating system', 'os'],
    name: 'Operating System',
    icon: Monitor,
  },
  {
    id: 'updates',
    names: ['windows updates', 'updates', 'software updates'],
    name: 'Windows Updates',
    icon: RefreshCw,
  },
  {
    id: 'password_lock',
    names: ['password & lock', 'password and lock', 'password', 'screen lock'],
    name: 'Password & Lock',
    icon: Lock,
  },
  {
    id: 'disk_encryption',
    names: ['disk encryption', 'bitlocker', 'filevault'],
    name: 'Disk Encryption',
    icon: HardDrive,
  },
  {
    id: 'firewall',
    names: ['firewall'],
    name: 'Firewall',
    icon: Flame,
  },
  {
    id: 'antivirus',
    names: ['antivirus', 'anti virus', 'endpoint protection'],
    name: 'Antivirus',
    icon: Shield,
  },
];

const HIDDEN_CHECK_NAMES = new Set(['connectivity', 'network']);

const REMEDIATIONS = {
  os: {
    title: 'Review operating system data',
    action: 'Open Windows Update',
    uri: 'ms-settings:windowsupdate',
    steps: [
      'Install the latest Windows security updates.',
      'Restart the device if Windows asks for it.',
    ],
    why: 'Operating system device data confirms the device is supported and ready for access.',
  },
  updates: {
    title: 'Install Windows security update',
    action: 'Open Windows Update',
    uri: 'ms-settings:windowsupdate',
    steps: [
      'Install all pending Windows updates.',
      'Restart the device if Windows asks for it.',
    ],
    why: 'Security updates reduce exposure to known endpoint vulnerabilities.',
  },
  password_lock: {
    title: 'Set password and screen lock',
    action: 'Open sign-in options',
    uri: 'ms-settings:signinoptions',
    steps: [
      'Set a password or Windows Hello sign-in method.',
      'Enable automatic screen lock after inactivity.',
    ],
    why: 'Password and lock settings protect the device when it is unattended.',
  },
  disk_encryption: {
    title: 'Enable BitLocker protection',
    action: 'Open device encryption',
    uri: 'ms-settings:deviceencryption',
    steps: [
      'Turn on BitLocker or device encryption for the system drive.',
      'Wait until encryption finishes before retrying access.',
    ],
    why: 'Disk encryption protects company data if the device is lost or stolen.',
  },
  firewall: {
    title: 'Turn on Windows Firewall',
    action: 'Open Windows Security',
    uri: 'windowsdefender://firewall',
    steps: [
      'Enable Microsoft Defender Firewall for every network profile.',
      'Retry the health check after the profiles show as enabled.',
    ],
    why: 'Firewall protection blocks unwanted inbound connections to the device.',
  },
  antivirus: {
    title: 'Enable antivirus protection',
    action: 'Open Windows Security',
    uri: 'windowsdefender:',
    steps: [
      'Turn on real-time protection in Windows Security.',
      'Update antivirus definitions and retry the health check.',
    ],
    why: 'Antivirus protection helps detect malicious software before access is granted.',
  },
  connectivity: {
    title: 'Restore agent connectivity',
    action: 'Retry connection',
    steps: [
      'Connect to a network with internet access.',
      'Restart the TRUSTAGENT service if the device stays offline.',
    ],
    why: 'Connectivity is required so the endpoint can report device data and receive policy.',
  },
};

const DETAIL_LABELS_TO_HIDE = new Set([
  'compliance',
  'expected status',
  'observed status',
  'policy required',
]);

function SecurityView({ dashboard, error = '', loading = false }) {
  const [selectedId, setSelectedId] = useState('');
  const pipeUnavailable = useMemo(() => isPipeUnavailable(dashboard, error), [dashboard, error]);
  const rows = useMemo(
    () => buildHealthRows(dashboard, loading || pipeUnavailable),
    [dashboard, loading, pipeUnavailable],
  );
  const selectedRow = rows.find((row) => row.id === selectedId);

  if (selectedRow) {
    return (
      <section className="ml-[76px] h-full overflow-hidden bg-[#f9faf9] text-[#202427]">
        <RemediationView row={selectedRow} onBack={() => setSelectedId('')} />
      </section>
    );
  }

  return (
    <section className="ml-[76px] h-full overflow-hidden bg-[#f9faf9] text-[#202427]">
      <HealthHeader dashboard={dashboard} checking={loading || pipeUnavailable} />
      <HealthList rows={rows} onSelect={setSelectedId} />
      <HealthFooter dashboard={dashboard} checking={loading || pipeUnavailable} />
    </section>
  );
}

function HealthHeader({ dashboard, checking }) {
  const hostname = dashboard?.device_data?.hostname || dashboard?.device_data?.device_id || 'Checking device';
  const osName = dashboard?.device_data?.os || findCheck(dashboard, 'os')?.description || 'Your System';

  return (
    <header className="px-5 py-4">
      <div className="mb-3 flex items-center">
        <p className="text-lg font-extrabold leading-none text-[#1f262b]">Health Check</p>
      </div>
      <div className="flex min-w-0 items-center gap-3">
        <div className="grid h-14 w-14 shrink-0 place-items-center rounded-md border border-[#cdd1d3] bg-[#f0f2f2] text-[#334045]">
          <Laptop className="h-10 w-10" strokeWidth={2.2} />
        </div>
        <div className="min-w-0">
          <h1 className="truncate text-2xl font-medium leading-none text-[#111820]">Your System</h1>
          <p className="mt-1 truncate text-xs font-semibold text-[#6b737a]">{hostname}</p>
          <p className="mt-0.5 truncate text-xs text-[#6b737a]">{checking ? 'Collecting device data' : osName}</p>
        </div>
      </div>
    </header>
  );
}

function HealthList({ rows, onSelect }) {
  return (
    <div className="border-y border-[#e3e4e5]">
      {rows.map((row) => (
        <HealthRow key={row.id} row={row} onSelect={onSelect} />
      ))}
    </div>
  );
}

function HealthRow({ row, onSelect }) {
  const status = normalizeStatus(row.status);
  const Icon = row.icon || HelpCircle;
  const actionable = isActionable(row);
  const content = (
    <>
      <div className="grid h-full w-10 shrink-0 place-items-center">
        <StatusIcon status={status} loading={row.loading} />
      </div>
      <div className="grid h-10 w-10 shrink-0 place-items-center text-[#4b5358]">
        <Icon className="h-6 w-6" strokeWidth={2.4} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-base font-medium leading-5 text-[#1e252b]">{row.title}</p>
        {row.subtitle ? (
          <p className="mt-0.5 truncate text-xs font-medium text-[#6e767d]">{row.subtitle}</p>
        ) : null}
      </div>
      {actionable ? (
        <ChevronRight className="h-5 w-5 shrink-0 text-[#687078]" strokeWidth={2.5} />
      ) : null}
    </>
  );

  if (actionable) {
    return (
      <button
        type="button"
        className="flex h-[52px] w-full items-center gap-2 px-5 text-left transition-colors duration-150 hover:bg-[#eef1f1]"
        onClick={() => onSelect(row.id)}
      >
        {content}
      </button>
    );
  }

  return (
    <div className="flex h-[52px] items-center gap-2 px-5">
      {content}
    </div>
  );
}

function StatusIcon({ status, loading }) {
  if (loading || status === 'checking') {
    return (
      <span className="grid h-6 w-6 place-items-center rounded-full bg-[#e2ecec] text-[var(--accent)]">
        <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2.7} />
      </span>
    );
  }

  if (status === 'good') {
    return (
      <span className="grid h-6 w-6 place-items-center rounded-full bg-[#dbeedc] text-[#2f7d32]">
        <CheckCircle className="h-4 w-4" strokeWidth={3} />
      </span>
    );
  }

  if (status === 'warning') {
    return (
      <span className="grid h-6 w-6 place-items-center rounded-full bg-[#fff1c7] text-[#9a6500]">
        <AlertCircle className="h-4 w-4" strokeWidth={2.8} />
      </span>
    );
  }

  if (status === 'critical') {
    return (
      <span className="grid h-6 w-6 place-items-center rounded-full bg-[#ffd9d5] text-[#b42318]">
        <AlertCircle className="h-4 w-4" strokeWidth={2.8} />
      </span>
    );
  }

  return (
    <span className="grid h-6 w-6 place-items-center rounded-full bg-[#e6e8ea] text-[#697177]">
      <HelpCircle className="h-4 w-4" strokeWidth={2.7} />
    </span>
  );
}

function HealthFooter({ dashboard, checking }) {
  const collectedAt = dashboard?.device_data?.collected_at;
  const footerText = checking ? 'Collecting device health data' : `Last checked ${formatDateTime(collectedAt)}`;

  return (
    <footer className="px-5 py-3 text-xs font-semibold text-[#5f686e]">
      <p className="truncate">{footerText}</p>
    </footer>
  );
}

function RemediationView({ row, onBack }) {
  const remediation = getRemediation(row);
  const details = detailEntries(row.details);

  return (
    <div className="flex h-full flex-col">
      <header className="flex h-12 shrink-0 items-center gap-3 border-b border-[#dedede] px-4">
        <button
          type="button"
          className="grid h-8 w-8 place-items-center rounded-md text-[#4b5358] transition-colors duration-150 hover:bg-[#eef1f1]"
          onClick={onBack}
          title="Back"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <p className="truncate text-sm font-bold text-[#1f262b]">{row.name}</p>
      </header>

      <div className="min-h-0 flex-1 overflow-auto px-8 pb-8 pt-2">
        <h2 className="mb-5 text-base font-bold text-[#1f262b]">{remediation.title}</h2>

        <ol className="space-y-4">
          <li className="flex items-center gap-3">
            <StepNumber value="1" />
            <button
              type="button"
              className="inline-flex min-h-10 items-center gap-2 rounded-md bg-[var(--accent)] px-6 text-sm font-bold text-white transition-colors duration-150 hover:bg-[#245256]"
              onClick={() => openRemediationUri(remediation.uri)}
            >
              <span>{remediation.action}</span>
              <ExternalLink className="h-4 w-4" />
            </button>
          </li>
          {remediation.steps.map((step, index) => (
            <li key={step} className="flex items-start gap-3">
              <StepNumber value={String(index + 2)} />
              <p className="pt-1 text-sm font-semibold text-[#4b5358]">{step}</p>
            </li>
          ))}
        </ol>

        <p className="mt-6 text-sm font-semibold text-[var(--accent)]">{remediation.why}</p>

        {row.description ? (
          <p className="mt-5 rounded-md border border-[#d5d9da] bg-[#f0f2f2] px-4 py-3 text-sm font-semibold text-[#1f262b]">
            {row.description}
          </p>
        ) : null}

        {details.length > 0 ? (
          <div className="mt-4 grid gap-2">
            {details.map(([label, value]) => (
              <div key={label} className="rounded-md border border-[#d5d9da] bg-[#fbfbfb] px-4 py-2">
                <p className="text-xs font-bold uppercase tracking-normal text-[#6e767d]">{label}</p>
                <p className="truncate text-sm font-semibold text-[#1f262b]">{value}</p>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function StepNumber({ value }) {
  return (
    <span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[#e2ecec] text-xs font-bold text-[var(--accent)]">
      {value}
    </span>
  );
}

function buildHealthRows(dashboard, checking) {
  if (checking) {
    return CHECKS.map((config) => ({
      ...config,
      status: 'checking',
      title: checkingTitle(config),
      subtitle: 'Checking status',
      loading: true,
      details: {},
    }));
  }

  const checks = Array.isArray(dashboard?.device_data?.checks) ? dashboard.device_data.checks : [];
  if (checks.length === 0) {
    return CHECKS.map((config) => ({
      ...config,
      status: 'checking',
      title: checkingTitle(config),
      subtitle: 'Waiting for data',
      loading: true,
      details: {},
    }));
  }

  const rows = [];
  const used = new Set();

  CHECKS.forEach((config) => {
    const matchIndex = checks.findIndex((check, index) => !used.has(index) && matchesCheck(config, check?.name));
    if (matchIndex === -1) {
      rows.push({
        ...config,
        status: 'unavailable',
        title: `${config.name} is unavailable`,
        subtitle: 'No data reported yet',
        details: {},
      });
      return;
    }

    used.add(matchIndex);
    rows.push(rowFromCheck(config, checks[matchIndex]));
  });

  checks.forEach((check, index) => {
    if (used.has(index)) {
      return;
    }
    if (isHiddenCheck(check?.name)) {
      return;
    }
    rows.push(rowFromCheck({
      id: `extra_${index}`,
      names: [String(check?.name || '').toLowerCase()],
      name: check?.name || 'Device Data Check',
      icon: HelpCircle,
    }, check));
  });

  return rows;
}

function rowFromCheck(config, check) {
  const status = normalizeStatus(check?.status);
  return {
    ...config,
    name: check?.name || config.name,
    status,
    title: healthTitle(config.id, status, check),
    subtitle: healthSubtitle(config.id, status, check),
    description: check?.description || '',
    details: check?.details || {},
    loading: false,
  };
}

function healthTitle(id, status, check) {
  const description = String(check?.description || '').trim();

  if (id === 'os') {
    return description || 'Operating system is detected';
  }
  if (id === 'updates') {
    return status === 'good' ? 'Windows is up to date' : 'Windows is not up to date';
  }
  if (id === 'password_lock') {
    if (status === 'good') return 'System password is set';
    if (status === 'warning') return 'Screen lock needs attention';
    return 'System password is not set';
  }
  if (id === 'disk_encryption') {
    return status === 'good' ? 'BitLocker is enabled' : 'BitLocker is not enabled';
  }
  if (id === 'firewall') {
    return status === 'good' ? 'Firewall is enabled' : 'Firewall is not enabled';
  }
  if (id === 'antivirus') {
    return status === 'good' ? 'Antivirus is enabled' : 'Antivirus needs attention';
  }
  return description || check?.name || 'Device data check';
}

function healthSubtitle(id, status, check) {
  if (status === 'good') {
    return '';
  }
  return String(check?.description || formatStatusLabel(status)).trim();
}

function checkingTitle(config) {
  if (config.id === 'updates') return 'Windows update status';
  if (config.id === 'password_lock') return 'System password status';
  if (config.id === 'disk_encryption') return 'BitLocker status';
  if (config.id === 'firewall') return 'Firewall status';
  if (config.id === 'antivirus') return 'Antivirus status';
  return 'Operating system status';
}

function isActionable(row) {
  const status = normalizeStatus(row.status);
  return !row.loading && ['warning', 'critical', 'unavailable'].includes(status);
}

function findCheck(dashboard, id) {
  const config = CHECKS.find((item) => item.id === id);
  const checks = Array.isArray(dashboard?.device_data?.checks) ? dashboard.device_data.checks : [];
  return checks.find((check) => matchesCheck(config, check?.name));
}

function matchesCheck(config, name) {
  if (!config || !name) return false;
  const normalized = normalizeName(name);
  return config.names.some((alias) => normalizeName(alias) === normalized);
}

function normalizeName(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/&/g, 'and')
    .replace(/\s+/g, ' ');
}

function isHiddenCheck(name) {
  return HIDDEN_CHECK_NAMES.has(normalizeName(name));
}

function isPipeUnavailable(dashboard, error) {
  const checks = Array.isArray(dashboard?.device_data?.checks) ? dashboard.device_data.checks : [];
  const signals = [
    error,
    dashboard?.connection?.message,
    dashboard?.connection?.service_state,
    dashboard?.status?.device_data_last_error,
    ...checks.map((check) => `${check?.name || ''} ${check?.description || ''} ${Object.values(check?.details || {}).join(' ')}`),
  ]
    .join(' ')
    .toLowerCase();

  return signals.includes('pipe')
    || signals.includes('ipc')
    || signals.includes('not reachable')
    || signals.includes('service unavailable');
}

function getRemediation(row) {
  return REMEDIATIONS[row.id] || {
    title: `Resolve ${row.name}`,
    action: 'Review settings',
    steps: ['Review the reported status and apply the required organization policy.'],
    why: 'This device data check must be healthy before the device can be considered compliant.',
  };
}

function detailEntries(details) {
  return Object.entries(details || {})
    .filter(([label, value]) => {
      const normalizedLabel = normalizeName(label);
      return value && !DETAIL_LABELS_TO_HIDE.has(normalizedLabel);
    })
    .slice(0, 6);
}

function openRemediationUri(uri) {
  if (!uri || !window?.open) {
    return;
  }
  window.open(uri, '_self');
}

export default SecurityView;

