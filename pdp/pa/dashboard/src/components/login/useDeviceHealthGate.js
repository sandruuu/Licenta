import { useCallback, useEffect, useRef, useState } from 'react';
import { usePublicConfig } from '../../config/publicConfig';
import { apiJSON } from './loginUtils';

function useDeviceHealthGate({ sessionId, oidcSessionId, setStep }) {
  const [healthGate, setHealthGate] = useState('checking');
  const [deviceHealth, setDeviceHealth] = useState(null);
  const healthIntervalRef = useRef(null);
  const publicConfig = usePublicConfig();
  const deviceHealthConfigured = Boolean(
    publicConfig.device_health_agent_url
    && publicConfig.device_health_timeout_ms
    && publicConfig.device_health_retry_ms,
  );

  const checkDeviceHealthAgent = useCallback(async () => {
    if (!deviceHealthConfigured) return null;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), publicConfig.device_health_timeout_ms);
    try {
      const resp = await fetch(`${publicConfig.device_health_agent_url}/health`, { mode: 'cors', signal: controller.signal });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data.status === 'ok' ? data : null;
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }, [deviceHealthConfigured, publicConfig.device_health_agent_url, publicConfig.device_health_timeout_ms]);

  const fetchAgentHealthStatus = useCallback(async () => {
    if (!deviceHealthConfigured) return null;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), publicConfig.device_health_timeout_ms);
    try {
      const resp = await fetch(`${publicConfig.device_health_agent_url}/status`, { mode: 'cors', signal: controller.signal });
      if (!resp.ok) return null;
      return await resp.json();
    } catch {
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }, [deviceHealthConfigured, publicConfig.device_health_agent_url, publicConfig.device_health_timeout_ms]);

  const stopHealthAutoRetry = useCallback(() => {
    if (healthIntervalRef.current) {
      clearInterval(healthIntervalRef.current);
      healthIntervalRef.current = null;
    }
  }, []);

  const performHealthCheck = useCallback(async () => {
    setHealthGate('checking');
    const alive = await checkDeviceHealthAgent();
    if (!alive) {
      setHealthGate('missing');
      return false;
    }

    stopHealthAutoRetry();
    const status = await fetchAgentHealthStatus();
    if (status && status.overall_score !== undefined) {
      setDeviceHealth({
        overall_score: status.overall_score,
        checks: status.checks || [],
      });
    }
    setStep('login');
    return true;
  }, [checkDeviceHealthAgent, fetchAgentHealthStatus, setStep, stopHealthAutoRetry]);

  const startHealthAutoRetry = useCallback(() => {
    if (!deviceHealthConfigured) return;
    if (healthIntervalRef.current) return;
    healthIntervalRef.current = setInterval(async () => {
      const alive = await checkDeviceHealthAgent();
      if (alive) await performHealthCheck();
    }, publicConfig.device_health_retry_ms);
  }, [checkDeviceHealthAgent, deviceHealthConfigured, performHealthCheck, publicConfig.device_health_retry_ms]);

  useEffect(() => {
    if (!sessionId) return undefined;

    let cancelled = false;
    apiJSON(`/api/auth/session-info?session=${encodeURIComponent(sessionId)}`)
      .then((data) => {
        if (!cancelled && data.device_health) setDeviceHealth(data.device_health);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, [sessionId]);

  useEffect(() => {
    if (!oidcSessionId || !deviceHealthConfigured) return undefined;

    let cancelled = false;
    performHealthCheck().then((ok) => {
      if (!cancelled && !ok) startHealthAutoRetry();
    });

    return () => {
      cancelled = true;
      stopHealthAutoRetry();
    };
  }, [deviceHealthConfigured, oidcSessionId, performHealthCheck, startHealthAutoRetry, stopHealthAutoRetry]);

  useEffect(() => stopHealthAutoRetry, [stopHealthAutoRetry]);

  return {
    healthGate,
    deviceHealth,
    performHealthCheck,
  };
}

export default useDeviceHealthGate;
