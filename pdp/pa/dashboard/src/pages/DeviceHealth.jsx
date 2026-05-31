import { useCallback, useEffect, useMemo, useState } from 'react';
import { Ban, CheckCircle2, Clock3, Laptop, RefreshCw, ShieldAlert } from 'lucide-react';
import { getDeviceDataReport, getDeviceDataReports, getEnrollments, revokeEnrollment } from '../api';
import PageHeader from '../components/ui/PageHeader';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';

function normalize(value) {
  return String(value || '').toLowerCase();
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function deviceDataInfo(checks = [], row = {}) {
  if (!row.has_report || checks.length === 0) return { text: 'No data', variant: 'neutral', rank: 'unknown' };
  if (checks.some((c) => c.status === 'critical')) return { text: 'Critical', variant: 'danger', rank: 'critical' };
  if (checks.some((c) => c.status === 'warning' || c.status === 'unavailable')) return { text: 'Warning', variant: 'warning', rank: 'warning' };
  return { text: 'Good', variant: 'success', rank: 'good' };
}

function checkVariant(status) {
  if (status === 'good') return 'success';
  if (status === 'critical') return 'danger';
  return 'warning';
}

function asList(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.value)) return data.value;
  return [];
}

function timeValue(ts) {
  if (!ts) return 0;
  const value = new Date(ts).getTime();
  return Number.isNaN(value) ? 0 : value;
}

function isEndpointEnrollment(enrollment) {
  return enrollment?.device_id && enrollment.component === 'endpoint' && enrollment.status === 'approved';
}

function enrollmentToDeviceRow(enrollment) {
  return {
    id: enrollment.id,
    enrollment_id: enrollment.id,
    device_id: enrollment.device_id,
    hostname: enrollment.hostname || '',
    os: '',
    checks: [],
    reported_at: '',
    enrolled_at: enrollment.enrolled_at || '',
    expires_at: enrollment.expires_at || '',
    username: enrollment.username || '',
    enrollment_status: enrollment.status || '',
    has_report: false,
  };
}

function mergeDeviceRows(deviceDataReports, enrollments) {
  const byDeviceID = new Map();

  for (const report of deviceDataReports) {
    if (!report?.device_id) continue;
    byDeviceID.set(report.device_id, { ...report, has_report: true });
  }

  for (const enrollment of enrollments) {
    if (!isEndpointEnrollment(enrollment)) continue;

    const existing = byDeviceID.get(enrollment.device_id);
    if (existing) {
      byDeviceID.set(enrollment.device_id, {
        ...existing,
        enrollment_id: enrollment.id || existing.enrollment_id,
        hostname: existing.hostname || enrollment.hostname || '',
        username: existing.username || enrollment.username || '',
        enrolled_at: existing.enrolled_at || enrollment.enrolled_at || '',
        expires_at: existing.expires_at || enrollment.expires_at || '',
        enrollment_status: existing.enrollment_status || enrollment.status || '',
      });
      continue;
    }

    byDeviceID.set(enrollment.device_id, enrollmentToDeviceRow(enrollment));
  }

  return Array.from(byDeviceID.values()).sort((a, b) => (
    timeValue(b.reported_at || b.enrolled_at) - timeValue(a.reported_at || a.enrolled_at)
  ));
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-4 border-b border-border-light py-3 last:border-b-0">
      <dt className="text-xs font-bold uppercase text-text-muted">{label}</dt>
      <dd className={`min-w-0 truncate text-sm font-semibold text-text-primary ${mono ? 'text-mono' : ''}`}>
        {value || '-'}
      </dd>
    </div>
  );
}

function EmptyState({ title, message }) {
  return (
    <div className="grid min-h-[260px] place-items-center text-center text-text-muted">
      <div>
        <p className="text-sm font-bold text-text-muted">{title}</p>
        {message && <p className="mt-1 text-xs font-medium">{message}</p>}
      </div>
    </div>
  );
}

function DeviceListSkeleton() {
  return (
    <div className="divide-y divide-border-light">
      {Array.from({ length: 3 }, (_, index) => (
        <div key={`device-skeleton-${index}`} className="px-4 py-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-3">
              <div className="h-9 w-9 shrink-0 animate-pulse rounded-md bg-border-light" />
              <div className="min-w-0 flex-1 space-y-2">
                <div className="h-4 w-36 animate-pulse rounded bg-border-light" />
                <div className="h-3 w-48 animate-pulse rounded bg-border-light" />
              </div>
            </div>
            <div className="h-5 w-16 animate-pulse rounded-full bg-border-light" />
          </div>
          <div className="mt-3 flex items-center justify-between gap-3">
            <div className="h-3 w-24 animate-pulse rounded bg-border-light" />
            <div className="h-3 w-28 animate-pulse rounded bg-border-light" />
          </div>
        </div>
      ))}
    </div>
  );
}

function HealthChecksSkeleton() {
  return (
    <div className="divide-y divide-border-light">
      {Array.from({ length: 3 }, (_, index) => (
        <div key={`check-skeleton-${index}`} className="grid gap-3 py-4 lg:grid-cols-[220px_120px_1fr] lg:items-start">
          <div className="space-y-2">
            <div className="h-4 w-36 animate-pulse rounded bg-border-light" />
            <div className="h-3 w-44 animate-pulse rounded bg-border-light" />
          </div>
          <div className="h-5 w-20 animate-pulse rounded-full bg-border-light" />
          <div className="space-y-2">
            <div className="h-4 w-full animate-pulse rounded bg-border-light" />
            <div className="h-4 w-2/3 animate-pulse rounded bg-border-light" />
          </div>
        </div>
      ))}
    </div>
  );
}

function formatCheckDetails(details) {
  if (!details) return '-';
  const entries = Object.entries(details);
  if (entries.length === 0) return '-';
  return entries.map(([key, value]) => `${key}: ${value}`).join(', ');
}

function DeviceListItem({ report, selected, onClick }) {
  const info = deviceDataInfo(report.checks || [], report);
  const primary = report.hostname || report.device_id || 'Unknown device';
  const subtitle = report.hostname ? report.device_id : 'Endpoint device';

  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full border-b border-border-light border-l-4 px-4 py-3 text-left transition-colors ${
        selected
          ? 'border-l-accent bg-accent-muted'
          : 'border-l-transparent hover:bg-surface-hover/60'
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-md bg-info-muted text-info">
            <Laptop size={17} />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-text-primary">{primary}</p>
            <p className="mt-1 truncate text-mono text-xs text-text-muted">{subtitle}</p>
          </div>
        </div>
        <Badge variant={info.variant}>{info.text}</Badge>
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 text-xs font-semibold text-text-muted">
        <span className="truncate">{report.username || 'No user'}</span>
        <span className="shrink-0">{report.has_report ? formatTime(report.reported_at) : 'No data'}</span>
      </div>
    </button>
  );
}

function HealthChecksList({ checks, hasReport, loading }) {
  if (loading) {
    return <HealthChecksSkeleton />;
  }

  if (!hasReport) {
    return <EmptyState title="No device data reported yet." message="The device is enrolled, but it has not sent device data yet." />;
  }

  if (!checks || checks.length === 0) {
    return <EmptyState title="No checks found for this report." />;
  }

  return (
    <div className="divide-y divide-border-light">
      {checks.map((check, index) => (
        <div key={`${check.name || 'check'}-${index}`} className="grid gap-3 py-4 lg:grid-cols-[220px_120px_1fr] lg:items-start">
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-text-primary">{check.name || '-'}</p>
            <p className="mt-1 truncate text-xs font-semibold text-text-muted">{check.description || '-'}</p>
          </div>
          <Badge variant={checkVariant(check.status)}>{check.status || '-'}</Badge>
          <p className="min-w-0 break-words text-sm font-semibold text-text-secondary">
            {formatCheckDetails(check.details)}
          </p>
        </div>
      ))}
    </div>
  );
}

export default function DeviceHealth() {
  const [reports, setReports] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [revokingEnrollment, setRevokingEnrollment] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [healthFilter, setHealthFilter] = useState('all');
  const [enrollmentFilter, setEnrollmentFilter] = useState('all');
  const [osFilter, setOsFilter] = useState('all');

  const loadList = useCallback(async () => {
    setLoadingList(true);
    setError('');
    try {
      const [deviceData, enrollmentData] = await Promise.all([
        getDeviceDataReports(),
        getEnrollments(),
      ]);
      const list = mergeDeviceRows(asList(deviceData), asList(enrollmentData));
      setReports(list);

      if (list.length === 0) {
        setSelectedDevice('');
        setSelectedReport(null);
        return;
      }

      setSelectedDevice((current) => {
        const keep = list.find((r) => r.device_id === current);
        return keep?.device_id || list[0].device_id;
      });
    } catch (e) {
      setError(e?.message || 'Failed to load device data');
    } finally {
      setLoadingList(false);
    }
  }, []);

  const loadDetail = useCallback(async (deviceId) => {
    if (!deviceId) {
      setSelectedReport(null);
      return;
    }
    const localReport = reports.find((report) => report.device_id === deviceId);
    if (localReport && !localReport.has_report) {
      setSelectedReport(localReport);
      return;
    }
    setLoadingDetail(true);
    setError('');
    try {
      const detail = await getDeviceDataReport(deviceId);
      setSelectedReport(detail ? { ...localReport, ...detail } : localReport || null);
    } catch (e) {
      setError(e?.message || 'Failed to load selected device data');
      setSelectedReport(null);
    } finally {
      setLoadingDetail(false);
    }
  }, [reports]);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  useEffect(() => {
    if (selectedDevice) {
      void loadDetail(selectedDevice);
    }
  }, [selectedDevice, loadDetail]);

  const osOptions = useMemo(() => {
    const values = new Set();
    reports.forEach((report) => {
      if (report.os) values.add(report.os);
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [reports]);

  const enrollmentOptions = useMemo(() => {
    const values = new Set();
    reports.forEach((report) => {
      if (report.enrollment_status) values.add(report.enrollment_status);
    });
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [reports]);

  const filteredReports = useMemo(() => {
    const needle = normalize(query.trim());
    return reports.filter((report) => {
      const info = deviceDataInfo(report.checks || [], report);
      if (healthFilter !== 'all' && info.rank !== healthFilter) return false;
      if (enrollmentFilter !== 'all' && report.enrollment_status !== enrollmentFilter) return false;
      if (osFilter !== 'all' && report.os !== osFilter) return false;
      if (!needle) return true;
      return [
        report.device_id,
        report.hostname,
        report.username,
        report.os,
        report.enrollment_status,
        info.text,
      ].some((value) => normalize(value).includes(needle));
    });
  }, [reports, query, healthFilter, enrollmentFilter, osFilter]);

  const hasFilters = query.trim() || healthFilter !== 'all' || enrollmentFilter !== 'all' || osFilter !== 'all';

  useEffect(() => {
    if (loadingList) return;
    if (filteredReports.length === 0) {
      if (selectedDevice) {
        setSelectedDevice('');
        setSelectedReport(null);
      }
      return;
    }
    const selectedStillVisible = filteredReports.some((report) => report.device_id === selectedDevice);
    if (!selectedStillVisible) {
      setSelectedDevice(filteredReports[0].device_id);
      setSelectedReport(null);
    }
  }, [filteredReports, loadingList, selectedDevice]);

  const selectedListRow = useMemo(
    () => reports.find((report) => report.device_id === selectedDevice) || null,
    [reports, selectedDevice],
  );

  const selected = selectedReport || selectedListRow;
  const selectedInfo = selected ? deviceDataInfo(selected.checks || [], selected) : null;

  const revokeSelectedEnrollment = async () => {
    const enrollmentID = selected?.enrollment_id;
    if (!enrollmentID || !confirm(`Revoke enrollment for device "${selectedDevice}" and terminate its active sessions?`)) return;
    setRevokingEnrollment(true);
    setError('');
    try {
      await revokeEnrollment(enrollmentID);
      await loadList();
      setSelectedReport(null);
    } catch (e) {
      setError(e?.message || 'Failed to revoke device enrollment');
    } finally {
      setRevokingEnrollment(false);
    }
  };

  return (
    <>
      <PageHeader title="Devices" />

      {error && (
        <div className="mb-5 rounded-md border border-danger bg-danger-muted p-3 text-sm font-semibold text-danger">{error}</div>
      )}

      <ListToolbar
        query={query}
        onQueryChange={setQuery}
        placeholder="Search hostname, user, device ID, or OS"
        summary={`${filteredReports.length} of ${reports.length}`}
      >
        <ListToolbarSelect value={healthFilter} onChange={setHealthFilter}>
          <option value="all">All health states</option>
          <option value="good">Good data</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
          <option value="unknown">No data</option>
        </ListToolbarSelect>
        <ListToolbarSelect value={enrollmentFilter} onChange={setEnrollmentFilter} className="sm:w-[190px]">
          <option value="all">All enrollments</option>
          {enrollmentOptions.map((status) => (
            <option key={status} value={status}>{status}</option>
          ))}
        </ListToolbarSelect>
        <ListToolbarSelect value={osFilter} onChange={setOsFilter}>
          <option value="all">All operating systems</option>
          {osOptions.map((os) => (
            <option key={os} value={os}>{os}</option>
          ))}
        </ListToolbarSelect>
      </ListToolbar>

      <div className="h-[calc(100vh-163px)] min-h-[520px] overflow-hidden rounded-md border border-border bg-surface-card shadow-surface">
        <div className="grid h-full grid-cols-1 xl:grid-cols-[360px_1fr]">
          <aside className="border-b border-border bg-surface-card xl:border-b-0 xl:border-r">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <div>
                <h3 className="text-sm font-bold text-text-primary">Endpoint Devices</h3>
                <p className="text-xs font-semibold text-text-muted">{filteredReports.length} of {reports.length} devices</p>
              </div>
              <Button variant="secondary" onClick={loadList} disabled={loadingList || loadingDetail}>
                <RefreshCw size={14} /> Refresh
              </Button>
            </div>

            <div className="h-[calc(100%-73px)] overflow-y-auto">
              {loadingList ? (
                <DeviceListSkeleton />
              ) : filteredReports.length === 0 ? (
                <EmptyState
                  title={hasFilters ? 'No devices match filters.' : 'No endpoint devices yet.'}
                  message={hasFilters ? 'Adjust search or filters to find devices.' : 'Enroll a TrustAgent device to see it here.'}
                />
              ) : (
                filteredReports.map((report) => (
                  <DeviceListItem
                    key={report.device_id || report.enrollment_id}
                    report={report}
                    selected={report.device_id === selectedDevice}
                    onClick={() => setSelectedDevice(report.device_id)}
                  />
                ))
              )}
            </div>
          </aside>

          <main className="min-w-0 overflow-y-auto bg-surface">
            {!selected ? (
              <EmptyState
                title={hasFilters ? 'No devices match filters.' : 'No endpoint devices yet.'}
                message={hasFilters ? 'Adjust search or filters to find devices.' : 'Enroll a TrustAgent device to see it here.'}
              />
            ) : (
              <>
                <div className="flex items-start justify-between gap-4 border-b border-border bg-surface-card px-6 py-5">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="truncate text-lg font-bold text-text-primary">{selected.hostname || selected.device_id}</h3>
                      {selectedInfo ? <Badge variant={selectedInfo.variant}>{selectedInfo.text}</Badge> : null}
                    </div>
                    <p className="mt-1 truncate text-mono text-xs text-text-muted">{selected.device_id}</p>
                  </div>
                  {selected.enrollment_id && selected.enrollment_status !== 'revoked' ? (
                    <Button variant="danger" onClick={revokeSelectedEnrollment} disabled={revokingEnrollment} title="Revoke device enrollment" aria-label="Revoke device enrollment">
                      <Ban size={14} /> Revoke
                    </Button>
                  ) : null}
                </div>

                <div className="grid grid-cols-1 gap-6 p-6 2xl:grid-cols-[360px_1fr]">
                  <section className="min-w-0">
                    <div className="mb-3 flex items-center gap-2">
                      <Laptop size={16} className="text-accent" />
                      <h4 className="text-sm font-bold text-text-primary">Device Information</h4>
                    </div>
                    <dl className="rounded-md border border-border-light bg-surface-card px-4">
                      <DetailRow label="Hostname" value={selected.hostname} />
                      <DetailRow label="User" value={selected.username} />
                      <DetailRow label="Operating System" value={selected.os} />
                      <DetailRow label="Last Report" value={selected.has_report ? formatTime(selected.reported_at) : 'No data'} mono />
                      <DetailRow label="Enrolled" value={formatTime(selected.enrolled_at)} mono />
                      <DetailRow label="Expires" value={formatTime(selected.expires_at)} mono />
                      <DetailRow label="Enrollment" value={selected.enrollment_status} />
                    </dl>
                  </section>

                  <section className="min-w-0">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        {selectedInfo?.rank === 'good' ? <CheckCircle2 size={16} className="text-success" /> : <ShieldAlert size={16} className="text-warning" />}
                        <h4 className="text-sm font-bold text-text-primary">Device Health Checks</h4>
                      </div>
                      <div className="flex items-center gap-2 text-xs font-semibold text-text-muted">
                        <Clock3 size={14} />
                        {selected.has_report ? formatTime(selected.reported_at) : 'No report'}
                      </div>
                    </div>
                    <div className="rounded-md border border-border-light bg-surface-card px-4">
                      <HealthChecksList
                        checks={selected.checks || []}
                        hasReport={selected.has_report}
                        loading={loadingDetail}
                      />
                    </div>
                  </section>
                </div>
              </>
            )}
          </main>
        </div>
      </div>
    </>
  );
}
