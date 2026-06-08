import { useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Background,
  Controls,
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
import { currentLocationPath, navigateWithReturn } from '../../utils/navigation';

const NODE_WIDTH = 280;
const NODE_HEIGHT = 86;
const NODE_X_GAP = 360;
const NODE_Y_GAP = 126;
const CANVAS_PADDING = 48;

const iconMap = {
  organization: Building2,
  gateway: Router,
  resource: Server,
  empty: Database,
};

const statusClass = {
  success: 'text-[#638f67]',
  warning: 'text-[#c7a23a]',
  danger: 'text-[#b46a62]',
  neutral: 'text-text-muted',
};

const iconClass = {
  organization: 'text-accent',
  gateway: 'text-accent',
  resource: 'text-[#638f67]',
  neutral: 'text-text-secondary',
};

const edgeColor = {
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  danger: 'var(--color-danger)',
  neutral: 'var(--color-text-secondary)',
};
const architectureCardClass = 'rounded-md border border-[rgba(44,97,100,0.55)] bg-[rgba(44,97,100,0.045)] shadow-[0_8px_16px_rgba(42,42,42,0.12)] transition-[border-color,background-color,box-shadow] duration-150 hover:border-accent hover:bg-[rgba(44,97,100,0.085)] hover:shadow-[0_10px_18px_rgba(42,42,42,0.14)]';

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
  const iconTone = iconClass[data.tone] || iconClass.neutral;
  const statusTone = statusClass[statusVariant(data.badge)] || statusClass.neutral;
  const showTarget = !data.isRoot;
  const showSource = data.hasChildren;

  return (
    <div
      className={`group relative w-[280px] px-4 py-4 ${architectureCardClass} ${
        isClickable ? 'cursor-pointer' : ''
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{
          width: 13,
          height: 13,
          left: -7,
          border: '3px solid var(--color-surface)',
          background: 'var(--color-text-secondary)',
          opacity: showTarget ? 1 : 0,
        }}
      />

      {data.badge && (
        <span className={`absolute right-4 top-3 text-[10px] font-bold uppercase tracking-[0.05em] ${statusTone}`}>
          {String(data.badge).toLowerCase()}
        </span>
      )}

      <div className="grid grid-cols-[24px_minmax(0,1fr)] items-center gap-3 pr-16">
        <span className={`flex shrink-0 items-center justify-center ${iconTone}`}>
          <Icon size={20} />
        </span>
        <div className="min-w-0">
          <div className="truncate text-[11px] font-semibold uppercase tracking-[0.08em] text-text-muted">{data.kicker}</div>
          <div className="mt-0.5 truncate text-[15px] font-semibold leading-5 text-text-primary">{data.label}</div>
          {data.subtitle && <div className="truncate text-[12px] font-medium text-text-secondary">{data.subtitle}</div>}
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 13,
          height: 13,
          right: -7,
          border: '3px solid var(--color-surface)',
          background: 'var(--color-text-secondary)',
          opacity: showSource ? 1 : 0,
        }}
      />
    </div>
  );
}

const nodeTypes = { architecture: ArchitectureNode };

function resourceSubtitle(resource) {
  const type = String(resource.type || 'resource').toUpperCase();
  if (resource.external_url) return resource.external_url;
  return resource.host ? `${type} target` : type;
}

function resourceProtocolLabel(resource) {
  const type = String(resource.type || 'resource').toUpperCase();
  return resource.port ? `${type} : ${resource.port}` : type;
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
  const organizationHref = `/organizations/${encode(organization.id)}`;
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
      href: `/gateways/${encode(gateway.id)}`,
      children: gatewayResources.length > 0
        ? gatewayResources.map((resource) => ({
            id: `resource:${resource.id}`,
            kicker: resourceProtocolLabel(resource),
            label: resource.name,
            subtitle: resourceSubtitle(resource),
            meta: resourceMeta(resource),
            metric: '',
            badge: resource.enabled ? 'enabled' : 'disabled',
            icon: 'resource',
            tone: 'resource',
            href: `/resources/${encode(resource.id)}`,
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
              href: `/gateways/${encode(gateway.id)}`,
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
  className = '',
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const { nodes, edges, height } = useMemo(() => layoutTree(buildTree({
    organization,
    gateways,
    resources,
  })), [organization, gateways, resources]);
  const containerClass = className || 'h-[min(640px,68vh)] min-h-[420px]';
  const containerStyle = className ? undefined : { maxHeight: `${Math.max(420, Math.min(680, height + 70))}px` };

  return (
    <div
      className={`${containerClass} overflow-hidden rounded-md bg-surface`}
      style={containerStyle}
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
          if (node.data?.href && node.data.href !== currentLocationPath(location)) {
            navigateWithReturn(navigate, node.data.href, location);
          }
        }}
        style={{ width: '100%', height: '100%' }}
      >
        <Background variant="dots" gap={34} size={1.05} color="rgba(44, 97, 100, 0.26)" />
        <Controls
          position="top-left"
          showInteractive={false}
          style={{
            border: '1px solid rgba(44, 97, 100, 0.25)',
            borderRadius: 8,
            boxShadow: '0 8px 18px rgba(42,42,42,0.12)',
            overflow: 'hidden',
          }}
        />
      </ReactFlow>
    </div>
  );
}
