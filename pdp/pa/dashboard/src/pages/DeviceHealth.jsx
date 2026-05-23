import { useCallback, useEffect, useMemo, useState } from 'react';
import { Clock3, RefreshCw, MonitorSmartphone, ShieldAlert, ShieldCheck } from 'lucide-react';
import { getDeviceDataReport, getDeviceDataReports, getEnrollments } from '../api';
import PageHeader from '../components/ui/PageHeader';
import DataTable from '../components/ui/DataTable';
import Badge from '../components/ui/Badge';
import StatCard from '../components/ui/StatCard';
import Button from '../components/ui/Button';

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

export default function DeviceHealth() {
  const [reports, setReports] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState('');

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
      setSelectedReport(detail || null);
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

  const summary = useMemo(() => {
    const total = reports.length;
    let good = 0;
    let warning = 0;
    let critical = 0;
    let unknown = 0;

    for (const report of reports) {
      const label = deviceDataInfo(report.checks || [], report);
      if (label.rank === 'good') good++;
      else if (label.rank === 'warning') warning++;
      else if (label.rank === 'critical') critical++;
      else unknown++;
    }

    return { total, good, warning, critical, unknown };
  }, [reports]);

  const deviceColumns = [
    {
      key: 'device_id',
      label: 'Device ID',
      render: (v, row) => (
        <span className={`text-mono ${row.device_id === selectedDevice ? 'text-accent-hover' : ''}`}>
          {row.device_id}
        </span>
      ),
    },
    { key: 'hostname', label: 'Hostname', render: (v) => v || '-' },
    { key: 'username', label: 'User', render: (v) => v || '-' },
    { key: 'os', label: 'OS', render: (v) => v || '-' },
    {
      key: 'checks',
      label: 'Checks',
      render: (v, row) => <span className="text-mono">{row.has_report ? (row.checks || []).length : '-'}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (v, row) => {
        const info = deviceDataInfo(row.checks || [], row);
        return <Badge variant={info.variant}>{info.text}</Badge>;
      },
    },
    {
      key: 'reported_at',
      label: 'Last Report',
      render: (v, row) => <span className="text-mono">{row.has_report ? formatTime(v) : 'No data'}</span>,
    },
    {
      key: 'enrolled_at',
      label: 'Enrolled',
      render: (v) => <span className="text-mono">{formatTime(v)}</span>,
    },
  ];

  const detailColumns = [
    { key: 'name', label: 'Check', render: (v) => v || '-' },
    {
      key: 'status',
      label: 'Status',
      render: (v) => <Badge variant={checkVariant(v)}>{v || '-'}</Badge>,
    },
    {
      key: 'description',
      label: 'Description',
      render: (v) => <span className="text-text-muted">{v || '-'}</span>,
    },
    {
      key: 'details',
      label: 'Details',
      render: (v) => {
        if (!v) return '-';
        const detailStr = Object.entries(v).map(([k, val]) => `${k}: ${val}`).join(', ');
        return <span className="text-text-muted">{detailStr}</span>;
      },
    },
  ];

  return (
    <>
      <PageHeader title="Devices" />

      {/* Stat Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <StatCard label="Total Devices" value={summary.total} icon={MonitorSmartphone} color="blue" />
        <StatCard label="Good Data" value={summary.good} icon={ShieldCheck} color="green" />
        <StatCard label="Warning" value={summary.warning} icon={ShieldAlert} color="orange" />
        <StatCard label="Critical" value={summary.critical} icon={ShieldAlert} color="red" />
        <StatCard label="No Data" value={summary.unknown} icon={Clock3} color="blue" />
      </div>

      {/* Device List */}
      <div className="bg-surface-card border border-border rounded-md shadow-surface mb-5">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary">Endpoint Devices</h3>
          <Button variant="secondary" onClick={loadList} disabled={loadingList || loadingDetail}>
            <RefreshCw size={14} /> Refresh
          </Button>
        </div>

        {error && (
          <div className="bg-danger-muted border border-danger rounded mx-6 mt-4 p-3 text-sm text-danger">{error}</div>
        )}

        <div className="p-4">
          <DataTable
            columns={deviceColumns}
            data={reports}
            loading={loadingList}
            emptyIcon={MonitorSmartphone}
            emptyTitle="No endpoint devices yet."
            emptyMessage="Enroll a TrustAgent device to see it here."
            getRowKey={(row) => row.device_id || row.enrollment_id}
            onRowClick={(row) => setSelectedDevice(row.device_id)}
          />
        </div>
      </div>

      {/* Selected Device Details */}
      <div className="bg-surface-card border border-border rounded-md shadow-surface">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary">Selected Device Details</h3>
          <span className="text-xs text-text-muted">{selectedDevice || 'No device selected'}</span>
        </div>
        <div className="p-4">
          <DataTable
            columns={detailColumns}
            data={selectedReport ? selectedReport.checks || [] : []}
            loading={loadingDetail}
            emptyTitle={!selectedDevice ? 'Select a device to view checks.' : selectedReport && !selectedReport.has_report ? 'No device data reported yet.' : 'No checks found for this report.'}
            emptyMessage={!selectedDevice ? 'Click on a device above to view its checks.' : selectedReport && !selectedReport.has_report ? 'The device is enrolled, but it has not sent device data yet.' : 'No checks found for this report.'}
          />
        </div>
      </div>
    </>
  );
}
