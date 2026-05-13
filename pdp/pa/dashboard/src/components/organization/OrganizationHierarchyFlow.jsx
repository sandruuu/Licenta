import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Background,
  Controls,
  Handle,
  MarkerType,
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
import Badge from '../ui/Badge';

const NODE_WIDTH = 236;
const NODE_HEIGHT = 68;
const NODE_X_GAP = 292;
const NODE_Y_GAP = 136;
const CANVAS_PADDING = 32;

const iconMap = {
  organization: Building2,
  gateway: Router,
  resource: Server,
  empty: Database,
};

const toneClass = {
  organization: 'bg-accent text-white',
  gateway: 'bg-accent-muted text-accent',
  resource: 'bg-success-muted text-success',
  neutral: 'bg-surface-secondary text-text-secondary',
};

function statusVariant(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'active' || value === 'enrolled' || value === 'enabled') return 'success';
  if (value === 'pending') return 'warning';
  if (value === 'revoked' || value === 'disabled') return 'danger';
  return 'neutral';
}

function encode(value) {
  return encodeURIComponent(value || '');
}

function ArchitectureNode({ data }) {
  const Icon = iconMap[data.icon] || Database;
  const isClickable = !!data.href;
  const tone = toneClass[data.tone] || toneClass.neutral;
  const shapeClass = data.icon === 'organization'
    ? 'rounded-[999px] border-accent/20 bg-accent text-white'
    : data.icon === 'gateway'
      ? 'rounded-[999px] border-border bg-surface-card'
      : 'rounded-[18px] border-border bg-surface-card';
  const textClass = data.icon === 'organization' ? 'text-white' : 'text-text-primary';
  const mutedClass = data.icon === 'organization' ? 'text-white/75' : 'text-text-muted';

  return (
    <div
      className={`relative w-[236px] border px-3 py-3 shadow-[0_8px_22px_rgba(15,23,42,0.08)] transition-colors ${shapeClass} ${
        isClickable ? 'cursor-pointer hover:border-accent-orange hover:bg-[rgba(255,95,31,0.08)] hover:text-text-primary' : ''
      }`}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ width: 10, height: 10, border: 0, background: 'transparent', opacity: 0 }}
      />
      <div className="flex items-center gap-3">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${tone}`}>
          <Icon size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className={`truncate text-sm font-semibold leading-5 ${textClass}`}>{data.label}</div>
              {data.subtitle && <div className={`mt-0.5 truncate text-[11px] font-medium ${mutedClass}`}>{data.subtitle}</div>}
            </div>
            {data.badge && (
              <Badge variant={statusVariant(data.badge)} className="shrink-0">
                {data.badge}
              </Badge>
            )}
          </div>
          {data.meta && <div className={`mt-1.5 truncate text-[11px] ${data.icon === 'organization' ? 'text-white/80' : 'text-text-secondary'}`}>{data.meta}</div>}
        </div>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ width: 10, height: 10, border: 0, background: 'transparent', opacity: 0 }}
      />
    </div>
  );
}

const nodeTypes = { architecture: ArchitectureNode };

function buildTree({
  organization,
  gateways,
  resources,
}) {
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
      label: gateway.name || gateway.id,
      subtitle: gateway.fqdn || 'Gateway',
      meta: `${gatewayResources.length} resource${gatewayResources.length === 1 ? '' : 's'}`,
      badge: gateway.status || 'active',
      icon: 'gateway',
      tone: 'gateway',
      href: `/dashboard/gateways/${encode(gateway.id)}`,
      children: gatewayResources.length > 0
        ? gatewayResources.map((resource) => ({
            id: `resource:${resource.id}`,
            label: resource.name || resource.id,
            subtitle: (resource.type || 'resource').toUpperCase(),
            meta: resource.host || resource.description || resource.id,
            badge: resource.enabled ? 'enabled' : 'disabled',
            icon: 'resource',
            tone: 'resource',
            href: `/dashboard/resources/${encode(resource.id)}`,
          }))
        : [
            {
              id: `gateway:${gateway.id}:empty`,
              label: 'No resources',
              subtitle: 'Attach a resource',
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
      label: 'No infrastructure',
      subtitle: 'Create a gateway',
      meta: 'Then attach resources',
      icon: 'empty',
      tone: 'neutral',
      href: organizationHref,
    });
  }

  return {
    id: `organization:${organization.id}`,
    label: organization.name || organization.id,
    subtitle: organization.domain || 'Organization',
    meta: `${gateways.length} gateway${gateways.length === 1 ? '' : 's'} / ${resources.length} resource${resources.length === 1 ? '' : 's'}`,
    icon: 'organization',
    tone: 'organization',
    href: organizationHref,
    children,
  };
}

function layoutTree(model) {
  const root = hierarchy(model);
  tree().nodeSize([NODE_X_GAP, NODE_Y_GAP])(root);

  const descendants = root.descendants();
  const minX = Math.min(...descendants.map((node) => node.x));
  const maxX = Math.max(...descendants.map((node) => node.x));
  const maxY = Math.max(...descendants.map((node) => node.y));

  const nodes = descendants.map((node) => ({
    id: node.data.id,
    type: 'architecture',
    position: {
      x: node.x - minX + CANVAS_PADDING,
      y: node.y + CANVAS_PADDING,
    },
    data: node.data,
    draggable: false,
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
  }));

  const edges = descendants
    .filter((node) => node.parent)
    .map((node) => ({
      id: `${node.parent.data.id}->${node.data.id}`,
      source: node.parent.data.id,
      target: node.data.id,
      type: 'smoothstep',
      selectable: false,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 16,
        height: 16,
        color: '#64748b',
      },
      style: {
        stroke: '#70819a',
        strokeWidth: 2.2,
      },
    }));

  return {
    nodes,
    edges,
    width: maxX - minX + NODE_WIDTH + CANVAS_PADDING * 2,
    height: maxY + NODE_HEIGHT + CANVAS_PADDING * 2,
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
      className="h-[min(680px,70vh)] min-h-[460px] overflow-hidden rounded-md border border-border bg-surface-card"
      style={{ maxHeight: `${Math.max(460, Math.min(720, height + 40))}px` }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        fitView
        fitViewOptions={{ padding: 0.18 }}
        minZoom={0.2}
        maxZoom={1.25}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => {
          if (node.data?.href) navigate(node.data.href);
        }}
        style={{ width: '100%', height: '100%' }}
      >
        <Background color="#e2e8f0" gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
