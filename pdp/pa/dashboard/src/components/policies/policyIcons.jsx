import {
  Building2,
  CheckCircle2,
  FileText,
  Layers3,
  MonitorCheck,
  Server,
  SlidersHorizontal,
  Users,
  XCircle,
  ShieldAlert,
} from 'lucide-react';

export const sectionIcons = {
  details: FileText,
  action: SlidersHorizontal,
  device: MonitorCheck,
};

export const layerIcons = {
  organization: Building2,
  group: Users,
  resource: Server,
  resource_group: Layers3,
};

export const actionIcons = {
  allow: CheckCircle2,
  mfa_required: ShieldAlert,
  deny: XCircle,
};
