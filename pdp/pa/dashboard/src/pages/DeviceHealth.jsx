import { useCallback, useEffect, useMemo, useState } from 'react';
import { Ban, Laptop } from 'lucide-react';
import { getDeviceDataReport, getDeviceDataReports, getEnrollments, revokeEnrollment } from '../api';
import PageHeader from '../components/ui/PageHeader';
import Button from '../components/ui/Button';
import ConfirmDialog from '../components/ui/ConfirmDialog';
import ListToolbar, { ListToolbarSelect } from '../components/ui/ListToolbar';
import StatusText from '../components/ui/StatusText';

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

function checkVariant(status) {
  if (status === 'good') return 'success';
  if (status === 'critical') return 'danger';
  return 'warning';
}

function hasSecurityStatus(report, status) {
  return (report.checks || []).some((check) => normalize(check.status) === status);
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
  return enrollment?.device_id && enrollment.component === 'endpoint';
}

function isApprovedEndpointEnrollment(enrollment) {
  return isEndpointEnrollment(enrollment) && enrollment.status === 'approved';
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
    tenant_id: enrollment.tenant_id || '',
    has_report: false,
  };
}

function rowLogicalKey(row) {
  const host = normalize(row.hostname).trim();
  const tenant = normalize(row.tenant_id).trim();
  if (host) return `${tenant}|hostname|${host}`;
  return `device|${row.device_id || row.enrollment_id || ''}`;
}

function newerTime(a, b) {
  return timeValue(a) >= timeValue(b) ? a : b;
}

function preferredReportRow(a, b) {
  if (!a?.has_report) return b?.has_report ? b : a;
  if (!b?.has_report) return a;
  return timeValue(b.reported_at) > timeValue(a.reported_at) ? b : a;
}

function preferredEnrollmentRow(a, b) {
  const aApproved = a?.enrollment_status === 'approved';
  const bApproved = b?.enrollment_status === 'approved';
  if (aApproved !== bApproved) return bApproved ? b : a;
  return timeValue(b?.enrolled_at || b?.expires_at) > timeValue(a?.enrolled_at || a?.expires_at) ? b : a;
}

function mergeDuplicateDeviceRow(a, b) {
  const report = preferredReportRow(a, b) || a || b;
  const enrollment = preferredEnrollmentRow(a, b) || report;
  return {
    ...report,
    id: enrollment.enrollment_id || report.id,
    enrollment_id: enrollment.enrollment_id || report.enrollment_id,
    hostname: report.hostname || enrollment.hostname || '',
    username: enrollment.username || report.username || '',
    enrolled_at: newerTime(enrollment.enrolled_at, report.enrolled_at),
    expires_at: newerTime(enrollment.expires_at, report.expires_at),
    enrollment_status: enrollment.enrollment_status || report.enrollment_status || '',
    tenant_id: report.tenant_id || enrollment.tenant_id || '',
  };
}

function dedupeDeviceRows(rows) {
  const byLogicalDevice = new Map();
  for (const row of rows) {
    const key = rowLogicalKey(row);
    const existing = byLogicalDevice.get(key);
    byLogicalDevice.set(key, existing ? mergeDuplicateDeviceRow(existing, row) : row);
  }
  return Array.from(byLogicalDevice.values());
}

function mergeDeviceRows(deviceDataReports, enrollments) {
  const byDeviceID = new Map();
  const enrollmentsByDeviceID = new Map();

  for (const enrollment of enrollments) {
    if (!isEndpointEnrollment(enrollment)) continue;
    enrollmentsByDeviceID.set(enrollment.device_id, enrollment);
  }

  for (const report of deviceDataReports) {
    if (!report?.device_id) continue;
    const enrollment = enrollmentsByDeviceID.get(report.device_id);
    byDeviceID.set(report.device_id, {
      ...report,
      enrollment_id: enrollment?.id || '',
      username: enrollment?.username || '',
      enrolled_at: enrollment?.enrolled_at || '',
      expires_at: enrollment?.expires_at || '',
      enrollment_status: enrollment?.status || '',
      tenant_id: report.tenant_id || enrollment?.tenant_id || '',
      has_report: true,
    });
  }

  for (const enrollment of enrollments) {
    if (!isApprovedEndpointEnrollment(enrollment)) continue;

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
        tenant_id: existing.tenant_id || enrollment.tenant_id || '',
      });
      continue;
    }

    byDeviceID.set(enrollment.device_id, enrollmentToDeviceRow(enrollment));
  }

  return dedupeDeviceRows(Array.from(byDeviceID.values())).sort((a, b) => (
    timeValue(b.reported_at || b.enrolled_at) - timeValue(a.reported_at || a.enrolled_at)
  ));
}

function enrollmentStatusInfo(status) {
  const normalized = normalize(status);
  if (normalized === 'revoked') return { label: 'REVOKED', variant: 'danger', filter: 'revoked' };
  if (normalized === 'approved' || normalized === 'enrolled') return { label: 'ENROLLED', variant: 'success', filter: 'enrolled' };
  return { label: 'UNENROLLED', variant: 'warning', filter: 'unenrolled' };
}

function DetailField({ label, value, mono = false, children }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-bold uppercase tracking-[0.08em] text-text-muted">{label}</dt>
      <dd className={`mt-3 min-w-0 truncate text-sm font-bold text-text-primary ${mono ? 'text-mono text-xs' : ''}`}>
        {children || value || '-'}
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
    <div className="space-y-3">
      {Array.from({ length: 3 }, (_, index) => (
        <div
          key={`device-skeleton-${index}`}
          className="min-h-[92px] rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] px-5 py-4 shadow-[0_8px_16px_rgba(42,42,42,0.12)]"
        >
          <div className="flex min-w-0 items-center gap-3">
            <div className="h-5 w-5 shrink-0 animate-pulse rounded bg-border-light" />
            <div className="min-w-0 flex-1 space-y-2">
              <div className="h-4 w-36 animate-pulse rounded bg-border-light" />
              <div className="h-3 w-48 animate-pulse rounded bg-border-light" />
            </div>
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
        <div key={`check-skeleton-${index}`} className="grid gap-3 py-4 lg:grid-cols-[minmax(0,1fr)_120px] lg:items-start">
          <div className="space-y-2">
            <div className="h-4 w-36 animate-pulse rounded bg-border-light" />
            <div className="h-3 w-44 animate-pulse rounded bg-border-light" />
          </div>
          <div className="h-5 w-20 animate-pulse rounded-full bg-border-light" />
        </div>
      ))}
    </div>
  );
}

function DeviceListItem({ report, selected, onClick }) {
  const primary = report.hostname || report.device_id || 'Unknown device';
  const selectedClass = selected
    ? 'border-accent bg-[rgba(44,97,100,0.085)] shadow-[0_10px_18px_rgba(42,42,42,0.14)]'
    : 'border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.12)] hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';
  const titleClass = selected ? 'text-base text-accent' : 'text-sm text-text-primary';

  return (
    <button
      type="button"
      onClick={onClick}
      className={`min-h-[92px] w-full rounded-md border px-5 py-4 text-left transition-[border-color,background-color,box-shadow] duration-150 ${selectedClass}`}
    >
      <div className="flex min-w-0 items-center gap-3">
        <Laptop size={19} className="shrink-0 text-accent" />
        <div className="min-w-0">
          <p className={`truncate font-bold ${titleClass}`}>{primary}</p>
          <p className="mt-1 truncate text-mono text-xs font-semibold text-text-muted">{report.device_id || '-'}</p>
        </div>
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
      {checks.map((check, index) => {
        const variant = checkVariant(check.status);
        return (
          <div key={`${check.name || 'check'}-${index}`} className="grid gap-3 py-4 lg:grid-cols-[minmax(0,1fr)_120px] lg:items-center">
            <div className="min-w-0">
              <p className="truncate text-sm font-bold text-text-primary">{check.name || '-'}</p>
              <p className="mt-1 truncate text-xs font-semibold text-text-muted">{check.description || '-'}</p>
            </div>
            <StatusText variant={variant} className={variant === 'warning' ? '!text-[#d58b42]' : ''}>
              {check.status || '-'}
            </StatusText>
          </div>
        );
      })}
    </div>
  );
}

export default function DeviceHealth() {
  const [reports, setReports] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [revokeDeviceTarget, setRevokeDeviceTarget] = useState(null);
  const [revokingEnrollment, setRevokingEnrollment] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [securityDataFilter, setSecurityDataFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

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

  const filteredReports = useMemo(() => {
    const needle = normalize(query.trim());
    return reports.filter((report) => {
      const statusInfo = enrollmentStatusInfo(report.enrollment_status);
      if (securityDataFilter !== 'all' && !hasSecurityStatus(report, securityDataFilter)) return false;
      if (statusFilter !== 'all' && statusInfo.filter !== statusFilter) return false;
      if (!needle) return true;
      return [
        report.device_id,
        report.hostname,
        report.username,
        report.os,
        report.enrollment_status,
        statusInfo.label,
        ...(report.checks || []).flatMap((check) => [check.name, check.description, check.status]),
      ].some((value) => normalize(value).includes(needle));
    });
  }, [reports, query, securityDataFilter, statusFilter]);

  const hasFilters = query.trim() || securityDataFilter !== 'all' || statusFilter !== 'all';

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
  const enrollmentStatus = selected ? enrollmentStatusInfo(selected.enrollment_status) : null;

  const openRevokeDeviceModal = () => {
    if (!selected?.enrollment_id) return;
    setRevokeDeviceTarget({
      enrollmentID: selected.enrollment_id,
      name: selected.hostname || selected.device_id || selectedDevice,
    });
  };

  const confirmRevokeDevice = async () => {
    if (!revokeDeviceTarget?.enrollmentID) return;
    setRevokingEnrollment(true);
    setError('');
    try {
      await revokeEnrollment(revokeDeviceTarget.enrollmentID);
      await loadList();
      setSelectedReport(null);
      setRevokeDeviceTarget(null);
    } catch (e) {
      setError(e?.message || 'Failed to revoke device enrollment');
    } finally {
      setRevokingEnrollment(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <div className="shrink-0">
        <PageHeader title="Devices" subtitle="Review endpoint devices and their security data" />
      </div>

      {error && (
        <div className="mb-5 shrink-0 rounded-md border border-danger bg-danger-muted p-3 text-sm font-semibold text-danger">{error}</div>
      )}

      <div className="shrink-0">
        <ListToolbar
          query={query}
          onQueryChange={setQuery}
          placeholder="Search hostname, user, device ID, or OS"
          summary={`${filteredReports.length} of ${reports.length}`}
          className="px-0.5"
        >
          <ListToolbarSelect value={securityDataFilter} onChange={setSecurityDataFilter} className="sm:w-[190px]">
            <option value="all">All security data</option>
            <option value="unavailable">Unavailable</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </ListToolbarSelect>
          <ListToolbarSelect value={statusFilter} onChange={setStatusFilter} className="sm:w-[170px]">
            <option value="all">All statuses</option>
            <option value="enrolled">Enrolled</option>
            <option value="unenrolled">Unenrolled</option>
            <option value="revoked">Revoked</option>
          </ListToolbarSelect>
        </ListToolbar>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-6 overflow-hidden xl:grid-cols-[300px_minmax(0,1040px)]">
        <aside className="min-h-0 overflow-hidden rounded-md border border-border bg-transparent">
          <div className="h-full overflow-y-auto p-3">
            {loadingList ? (
              <DeviceListSkeleton />
            ) : filteredReports.length === 0 ? (
              <EmptyState
                title={hasFilters ? 'No devices match filters.' : 'No endpoint devices yet.'}
                message={hasFilters ? 'Adjust search or filters to find devices.' : 'Enroll a TrustAgent device to see it here.'}
              />
            ) : (
              <div className="space-y-3">
                {filteredReports.map((report) => (
                  <DeviceListItem
                    key={report.device_id || report.enrollment_id}
                    report={report}
                    selected={report.device_id === selectedDevice}
                    onClick={() => setSelectedDevice(report.device_id)}
                  />
                ))}
              </div>
            )}
          </div>
        </aside>

        <main className="min-w-0 overflow-y-auto pr-4 [scrollbar-gutter:stable]">
          {!selected ? (
            <div aria-hidden="true" />
          ) : (
            <>
              <div className="mb-4 flex justify-end">
                {selected.enrollment_id && selected.enrollment_status !== 'revoked' ? (
                  <Button variant="danger" onClick={openRevokeDeviceModal} disabled={revokingEnrollment} title="Revoke device enrollment" aria-label="Revoke device enrollment">
                    <Ban size={14} /> Revoke
                  </Button>
                ) : null}
              </div>

              <div className="grid gap-7">
                <section className="min-w-0">
                  <h4 className="text-[22px] font-bold leading-tight text-text-primary">Device informations</h4>
                  <dl className="mt-5 grid grid-cols-1 gap-x-10 gap-y-6 md:grid-cols-2 xl:grid-cols-3">
                    <DetailField label="Hostname" value={selected.hostname} />
                    <DetailField label="Enrolled by" value={selected.username} />
                    <DetailField label="Operating System" value={selected.os} />
                    <DetailField label="Last Report" value={selected.has_report ? formatTime(selected.reported_at) : 'No data'} mono />
                    <DetailField label="Enrolled" value={formatTime(selected.enrolled_at)} mono />
                    <DetailField label="Status">
                      <StatusText variant={enrollmentStatus.variant} className="text-sm leading-5">
                        {enrollmentStatus.label}
                      </StatusText>
                    </DetailField>
                  </dl>
                </section>

                <section className="min-w-0">
                  <h4 className="text-[22px] font-bold leading-tight text-text-primary">Device security data</h4>
                  <div className="mt-4">
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

      <ConfirmDialog
        open={!!revokeDeviceTarget}
        onClose={() => setRevokeDeviceTarget(null)}
        onConfirm={confirmRevokeDevice}
        title="Revoke device enrollment"
        message={revokeDeviceTarget ? `Revoke enrollment for "${revokeDeviceTarget.name}" and terminate its active sessions?` : ''}
        confirmLabel="Revoke"
        loadingLabel="Revoking..."
        loading={revokingEnrollment}
      />
    </div>
  );
}
