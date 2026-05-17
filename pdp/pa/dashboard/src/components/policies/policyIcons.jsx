import {
  Building2,
  CheckCircle2,
  FileText,
  Layers3,
  Server,
  SlidersHorizontal,
  Users,
  XCircle,
  ShieldAlert,
  LaptopMinimalCheck,
} from 'lucide-react';

export const sectionIcons = {
  details: FileText,
  action: SlidersHorizontal,
  device: LaptopMinimalCheck,
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
