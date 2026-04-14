import { useEffect, useMemo, useState } from 'react';
import { RefreshCw, MonitorSmartphone, ShieldAlert, ShieldCheck } from 'lucide-react';
import { getDeviceHealthReport, getDeviceHealthReports } from '../api';

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString('ro-RO', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function scoreLabel(score) {
  if (score >= 80) return { text: 'Good', cls: 'badge-allow' };
  if (score >= 60) return { text: 'Warning', cls: 'badge-mfa' };
  return { text: 'Critical', cls: 'badge-deny' };
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
      const data = await getDeviceHealthReports();
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
      setError(e?.message || 'Failed to load device health reports');
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
      const detail = await getDeviceHealthReport(deviceId);
      setSelectedReport(detail || null);
    } catch (e) {
      setError(e?.message || 'Failed to load selected device details');
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

    for (const r of reports) {
      if ((r.overall_score || 0) >= 80) good++;
      else if ((r.overall_score || 0) >= 60) warning++;
      else critical++;
    }

    return { total, good, warning, critical };
  }, [reports]);

  return (
    <>
      <div className="page-header">
        <h2>Device Health</h2>
        <p>View health telemetry sent by the Device Health Agent to Cloud.</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Total Devices</span>
            <div className="stat-card-icon blue"><MonitorSmartphone /></div>
          </div>
          <div className="stat-card-value">{summary.total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Good Posture</span>
            <div className="stat-card-icon green"><ShieldCheck /></div>
          </div>
          <div className="stat-card-value">{summary.good}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Warning</span>
            <div className="stat-card-icon orange"><ShieldAlert /></div>
          </div>
          <div className="stat-card-value">{summary.warning}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-header">
            <span>Critical</span>
            <div className="stat-card-icon red"><ShieldAlert /></div>
          </div>
          <div className="stat-card-value">{summary.critical}</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <h3>Reported Devices</h3>
          <button className="btn btn-secondary" onClick={loadList} disabled={loadingList || loadingDetail}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>

        {error && <div className="login-error" style={{ margin: 16 }}>{error}</div>}

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Device ID</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Score</th>
                <th>Status</th>
                <th>Last Report</th>
              </tr>
            </thead>
            <tbody>
              {loadingList ? (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Loading...</td></tr>
              ) : reports.length === 0 ? (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No device reports yet.</td></tr>
              ) : (
                reports.map((r) => {
                  const label = scoreLabel(r.overall_score || 0);
                  const isSelected = r.device_id === selectedDevice;
                  return (
                    <tr key={r.device_id} onClick={() => setSelectedDevice(r.device_id)} style={{ cursor: 'pointer' }}>
                      <td className="text-mono" style={isSelected ? { color: 'var(--accent-hover)' } : {}}>{r.device_id}</td>
                      <td>{r.hostname || '-'}</td>
                      <td>{r.os || '-'}</td>
                      <td className="text-mono">{r.overall_score ?? 0}</td>
                      <td><span className={`badge ${label.cls}`}>{label.text}</span></td>
                      <td className="text-mono">{formatTime(r.reported_at)}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Selected Device Details</h3>
          <span className="text-sm text-muted">{selectedDevice || 'No device selected'}</span>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Description</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {loadingDetail ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Loading details...</td></tr>
              ) : !selectedReport ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>Select a device to view checks.</td></tr>
              ) : (selectedReport.checks || []).length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No checks found for this report.</td></tr>
              ) : (
                selectedReport.checks.map((c, idx) => {
                  const cls = c.status === 'good' ? 'badge-allow' : c.status === 'warning' ? 'badge-mfa' : 'badge-deny';
                  const details = c.details ? Object.entries(c.details).map(([k, v]) => `${k}: ${v}`).join(', ') : '-';
                  return (
                    <tr key={`${c.name}-${idx}`}>
                      <td>{c.name || '-'}</td>
                      <td><span className={`badge ${cls}`}>{c.status || '-'}</span></td>
                      <td className="text-sm text-muted">{c.description || '-'}</td>
                      <td className="text-sm text-muted">{details}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
