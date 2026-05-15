import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Handle,
  Position,
  ReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { hierarchy, tree } from 'd3-hierarchy';
import {
  Building2,
  Database,
  Router,
  Server,
} from 'lucide-react';

const NODE_WIDTH = 280;
const NODE_HEIGHT = 82;
const NODE_X_GAP = 360;
const NODE_Y_GAP = 118;
const CANVAS_PADDING = 48;

const iconMap = {
  organization: Building2,
  gateway: Router,
  resource: Server,
  empty: Database,
};

const avatarClass = {
  organization: 'bg-accent text-white-smoke',
  gateway: 'bg-accent-muted text-accent',
  resource: 'bg-success-muted text-success',
  neutral: 'bg-surface-secondary text-text-secondary',
};

const statusClass = {
  success: 'border-success/30 bg-success-muted text-success',
  warning: 'border-warning/30 bg-warning-muted text-warning',
  danger: 'border-danger/30 bg-danger-muted text-danger',
  neutral: 'border-border bg-surface-secondary text-text-secondary',
};

const edgeColor = {
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  danger: 'var(--color-danger)',
  neutral: 'var(--color-text-secondary)',
};

function statusVariant(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'active' || value === 'enrolled' || value === 'enabled') return 'success';
  if (value === 'pending') return 'warning';
  if (value === 'revoked' || value === 'disabled') return 'danger';
  return 'neutral';
}

function edgeVariant(parent, child, root) {
  const rootVariant = statusVariant(root.data.badge);
  if (rootVariant === 'danger') return 'danger';

  const parentVariant = statusVariant(parent.data.badge);
  const childVariant = statusVariant(child.data.badge);

  if (parent.data.icon === 'gateway' && (parentVariant === 'warning' || parentVariant === 'danger')) {
    return parentVariant;
  }

  if (childVariant === 'warning' || childVariant === 'danger') return childVariant;
  return 'success';
}

function encode(value) {
  return encodeURIComponent(value || '');
}

function ArchitectureNode({ data }) {
  const Icon = iconMap[data.icon] || Database;
  const isClickable = !!data.href;
  const avatarTone = avatarClass[data.tone] || avatarClass.neutral;
  const statusTone = statusClass[statusVariant(data.badge)] || statusClass.neutral;
  const showTarget = !data.isRoot;
  const showSource = data.hasChildren || data.tailLabel;

  return (
    <div
      className={`group relative w-[280px] rounded-md border border-border bg-surface-card px-4 py-3 shadow-panel transition-colors ${
        isClickable ? 'cursor-pointer hover:border-accent hover:bg-surface-hover' : ''
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{
          width: 13,
          height: 13,
          left: -7,
          border: '3px solid var(--color-surface-card)',
          background: 'var(--color-text-secondary)',
          opacity: showTarget ? 1 : 0,
        }}
      />

      <div className="grid grid-cols-[44px_minmax(0,1fr)_auto] items-center gap-3">
        <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full ${avatarTone}`}>
          <Icon size={18} />
        </span>
        <div className="min-w-0">
          <div className="truncate text-[11px] font-semibold uppercase tracking-[0.08em] text-text-muted">{data.kicker}</div>
          <div className="mt-0.5 truncate text-[15px] font-semibold leading-5 text-text-primary">{data.label}</div>
          {data.subtitle && <div className="truncate text-[12px] font-medium text-text-secondary">{data.subtitle}</div>}
        </div>
        {data.badge && (
          <span className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.05em] ${statusTone}`}>
            {String(data.badge).toLowerCase()}
          </span>
        )}
      </div>

      {data.meta && (
        <div className="mt-3 flex items-center justify-between gap-3 border-t border-border-light pt-2">
          <span className="truncate text-[11px] font-medium text-text-muted">{data.meta}</span>
          {data.metric && <span className="shrink-0 text-[11px] font-semibold text-text-secondary">{data.metric}</span>}
        </div>
      )}

      {data.tailLabel && (
        <div className="pointer-events-none absolute -right-[66px] top-1/2 flex -translate-y-1/2 items-center">
          <span className="h-[2px] w-7 bg-text-secondary" />
          <span className="flex h-10 min-w-10 items-center justify-center rounded-full bg-graphite px-3 text-sm font-bold text-white-smoke shadow-panel">
            {data.tailLabel}
          </span>
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 13,
          height: 13,
          right: -7,
          border: '3px solid var(--color-surface-card)',
          background: 'var(--color-text-secondary)',
          opacity: showSource ? 1 : 0,
        }}
      />
    </div>
  );
}

const nodeTypes = { architecture: ArchitectureNode };

function resourceTailLabel(resource) {
  if (resource.port) return String(resource.port);
  return String(resource.type || '').toUpperCase() || null;
}

function resourceSubtitle(resource) {
  const type = String(resource.type || 'resource').toUpperCase();
  if (resource.external_url) return resource.external_url;
  return resource.host ? `${type} target` : type;
}

function resourceMeta(resource) {
  if (resource.host) return resource.host;
  return resource.description || resource.id;
}

function withNodeFlags(node, isRoot = false) {
  const children = (node.children || []).map((child) => withNodeFlags(child));
  return {
    ...node,
    isRoot,
    hasChildren: children.length > 0,
    children,
  };
}

function buildTree({ organization, gateways, resources }) {
  const organizationHref = `/dashboard/organizations/${encode(organization.id)}`;
  const resourcesByGatewayID = new Map(gateways.map((gateway) => [gateway.id, []]));
  resources.forEach((resource) => {
    if (!resourcesByGatewayID.has(resource.gateway_id)) {
      resourcesByGatewayID.set(resource.gateway_id || 'unassigned', []);
    }
    resourcesByGatewayID.get(resource.gateway_id || 'unassigned').push(resource);
  });

  const children = gateways.map((gateway) => {
    const gatewayResources = resourcesByGatewayID.get(gateway.id) || [];
    return {
      id: `gateway:${gateway.id}`,
      kicker: 'Gateway',
      label: gateway.name,
      subtitle: gateway.fqdn || 'Edge connector',
      meta: `${gatewayResources.length} resource${gatewayResources.length === 1 ? '' : 's'}`,
      metric: '',
      badge: gateway.status,
      icon: 'gateway',
      tone: 'gateway',
      href: `/dashboard/gateways/${encode(gateway.id)}`,
      children: gatewayResources.length > 0
        ? gatewayResources.map((resource) => ({
            id: `resource:${resource.id}`,
            kicker: String(resource.type).toUpperCase(),
            label: resource.name,
            subtitle: resourceSubtitle(resource),
            meta: resourceMeta(resource),
            metric: '',
            badge: resource.enabled ? 'enabled' : 'disabled',
            tailLabel: resourceTailLabel(resource),
            icon: 'resource',
            tone: 'resource',
            href: `/dashboard/resources/${encode(resource.id)}`,
          }))
        : [
            {
              id: `gateway:${gateway.id}:empty`,
              kicker: 'Resource',
              label: 'No resources',
              subtitle: 'Attach a protected target',
              meta: 'Open gateway details',
              icon: 'empty',
              tone: 'neutral',
              href: `/dashboard/gateways/${encode(gateway.id)}`,
            },
          ],
    };
  });

  if (children.length === 0) {
    children.push({
      id: `empty:${organization.id}`,
      kicker: 'Gateway',
      label: 'No gateways',
      subtitle: 'Create the first connector',
      meta: 'Then attach protected resources',
      icon: 'empty',
      tone: 'neutral',
      href: organizationHref,
    });
  }

  return withNodeFlags({
    id: `organization:${organization.id}`,
    kicker: 'Organization',
    label: organization.name,
    subtitle: organization.domain || 'Primary domain not set',
    meta: `${gateways.length} gateway${gateways.length === 1 ? '' : 's'}`,
    metric: `${resources.length} resource${resources.length === 1 ? '' : 's'}`,
    badge: organization.enabled === false ? 'disabled' : 'enabled',
    icon: 'organization',
    tone: 'organization',
    href: organizationHref,
    children,
  }, true);
}

function layoutTree(model) {
  const root = hierarchy(model);
  tree().nodeSize([NODE_Y_GAP, NODE_X_GAP])(root);

  const descendants = root.descendants();
  const minRow = Math.min(...descendants.map((node) => node.x));
  const maxRow = Math.max(...descendants.map((node) => node.x));
  const maxDepth = Math.max(...descendants.map((node) => node.y));

  const nodes = descendants.map((node) => ({
    id: node.data.id,
    type: 'architecture',
    position: {
      x: node.y + CANVAS_PADDING,
      y: node.x - minRow + CANVAS_PADDING,
    },
    data: node.data,
    draggable: false,
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  }));

  const edges = descendants
    .filter((node) => node.parent)
    .map((node) => {
      const variant = edgeVariant(node.parent, node, root);

      return {
        id: `${node.parent.data.id}->${node.data.id}`,
        source: node.parent.data.id,
        target: node.data.id,
        type: 'smoothstep',
        selectable: false,
        pathOptions: { borderRadius: 28 },
        style: {
          stroke: edgeColor[variant] || edgeColor.neutral,
          strokeWidth: 2.8,
        },
      };
    });

  return {
    nodes,
    edges,
    width: maxDepth + NODE_WIDTH + CANVAS_PADDING * 2,
    height: maxRow - minRow + NODE_HEIGHT + CANVAS_PADDING * 2,
  };
}

export default function OrganizationHierarchyFlow({
  organization,
  gateways,
  resources,
}) {
  const navigate = useNavigate();
  const { nodes, edges, height } = useMemo(() => layoutTree(buildTree({
    organization,
    gateways,
    resources,
  })), [organization, gateways, resources]);

  return (
    <div
      className="h-[min(640px,68vh)] min-h-[420px] overflow-hidden rounded-md bg-surface"
      style={{ maxHeight: `${Math.max(420, Math.min(680, height + 70))}px` }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        fitView
        fitViewOptions={{ padding: 0.32 }}
        minZoom={0.25}
        maxZoom={1.2}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => {
          if (node.data?.href) navigate(node.data.href);
        }}
        style={{ width: '100%', height: '100%' }}
      />
    </div>
  );
}
