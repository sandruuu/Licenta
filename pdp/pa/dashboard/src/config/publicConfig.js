import { useEffect, useState } from 'react';

export const EMPTY_PUBLIC_CONFIG = {
  oidc_default_claim_mapping: {},
  resource_default_ports: {},
};

let cachedConfig = null;
let pendingConfig = null;

function mergePublicConfig(data = {}) {
  return {
    ...EMPTY_PUBLIC_CONFIG,
    ...data,
    oidc_default_claim_mapping: data.oidc_default_claim_mapping || {},
    resource_default_ports: data.resource_default_ports || {},
  };
}

export async function loadPublicConfig() {
  if (cachedConfig) return cachedConfig;
  if (!pendingConfig) {
    pendingConfig = fetch('/api/config/public')
      .then((resp) => {
        if (!resp.ok) throw new Error('Failed to load public PDP config');
        return resp.json();
      })
      .then((data) => mergePublicConfig(data || {}))
      .then((data) => {
        cachedConfig = data;
        return cachedConfig;
      })
      .catch((err) => {
        pendingConfig = null;
        throw err;
      });
  }
  return pendingConfig;
}

export function usePublicConfig() {
  const [config, setConfig] = useState(cachedConfig || EMPTY_PUBLIC_CONFIG);

  useEffect(() => {
    let cancelled = false;
    loadPublicConfig()
      .then((data) => {
        if (!cancelled) setConfig(data);
      })
      .catch(() => {
        if (!cancelled) setConfig(EMPTY_PUBLIC_CONFIG);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return config;
}
