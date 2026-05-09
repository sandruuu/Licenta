import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, MonitorSmartphone, ShieldAlert, ShieldCheck } from 'lucide-react';
import { getDevicePostureReport, getDevicePostureReports } from '../api';
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

function postureInfo(checks = []) {
  if (checks.some((c) => c.status === 'critical')) return { text: 'Critical', variant: 'danger', rank: 'critical' };
  if (checks.some((c) => c.status === 'warning' || c.status === 'unavailable')) return { text: 'Warning', variant: 'warning', rank: 'warning' };
  return { text: 'Good', variant: 'success', rank: 'good' };
}

function checkVariant(status) {
  if (status === 'good') return 'success';
  if (status === 'critical') return 'danger';
  return 'warning';
}

export default function DeviceHealth() {
  const [reports, setReports] = useState([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [error, setError] = useState('');

  const loadList = async () => {
    setLoadingList(true);
    setError('');
    try {
      const data = await getDevicePostureReports();
      const list = Array.isArray(data) ? data : [];
      setReports(list);

      if (list.length === 0) {
        setSelectedDevice('');
        setSelectedReport(null);
        return;
      }

      const keep = list.find((r) => r.device_id === selectedDevice);
      const next = keep?.device_id || list[0].device_id;
      setSelectedDevice(next);
    } catch (e) {
      setError(e?.message || 'Failed to load device posture reports');
    } finally {
      setLoadingList(false);
    }
  };

  const loadDetail = async (deviceId) => {
    if (!deviceId) {
      setSelectedReport(null);
      return;
    }
    setLoadingDetail(true);
    setError('');
    try {
      const detail = await getDevicePostureReport(deviceId);
      setSelectedReport(detail || null);
    } catch (e) {
      setError(e?.message || 'Failed to load selected device posture');
      setSelectedReport(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    loadList();
  }, []);

  useEffect(() => {
    if (selectedDevice) {
      loadDetail(selectedDevice);
    }
  }, [selectedDevice]);

  const summary = useMemo(() => {
    const total = reports.length;
    let good = 0;
    let warning = 0;
    let critical = 0;

    for (const report of reports) {
      const label = postureInfo(report.checks || []);
      if (label.rank === 'good') good++;
      else if (label.rank === 'warning') warning++;
      else critical++;
    }

    return { total, good, warning, critical };
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
    { key: 'os', label: 'OS', render: (v) => v || '-' },
    {
      key: 'checks',
      label: 'Checks',
      render: (v, row) => <span className="text-mono">{(row.checks || []).length}</span>,
    },
    {
      key: 'status',
      label: 'Status',
      render: (v, row) => {
        const info = postureInfo(row.checks || []);
        return <Badge variant={info.variant}>{info.text}</Badge>;
      },
    },
    {
      key: 'reported_at',
      label: 'Last Report',
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
      <PageHeader title="Device Health" />

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Devices" value={summary.total} icon={MonitorSmartphone} color="blue" />
        <StatCard label="Good Posture" value={summary.good} icon={ShieldCheck} color="green" />
        <StatCard label="Warning" value={summary.warning} icon={ShieldAlert} color="orange" />
        <StatCard label="Critical" value={summary.critical} icon={ShieldAlert} color="red" />
      </div>

      {/* Device List */}
      <div className="bg-surface-card border border-border rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.06)] mb-5">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary">Reported Devices</h3>
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
            emptyTitle="No device reports yet."
          />
        </div>
      </div>

      {/* Selected Device Details */}
      <div className="bg-surface-card border border-border rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-primary">Selected Device Details</h3>
          <span className="text-xs text-text-muted">{selectedDevice || 'No device selected'}</span>
        </div>
        <div className="p-4">
          <DataTable
            columns={detailColumns}
            data={selectedReport ? selectedReport.checks || [] : []}
            loading={loadingDetail}
            emptyTitle="Select a device to view checks."
            emptyMessage={!selectedDevice ? 'Click on a device above to view its posture checks.' : 'No checks found for this report.'}
          />
        </div>
      </div>
    </>
  );
}
