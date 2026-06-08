import {
  Building2,
  Check,
  FileText,
  Layers3,
  LockKeyhole,
  Network,
  Server,
  Users,
  XCircle,
  ShieldAlert,
  MapPinned,
  LaptopMinimalCheck,
  UserPlus,
} from 'lucide-react';

export const sectionIcons = {
  details: FileText,
  newuser: UserPlus,
  stepup: LockKeyhole,
  riskbasedauth: ShieldAlert,
  location: MapPinned,
  devicehealth: LaptopMinimalCheck,
  authorizednetworks: Network,
};

export const layerIcons = {
  organization: Building2,
  group: Users,
  resource: Server,
  resource_group: Layers3,
};

export const actionIcons = {
  allow: Check,
  step_up_required: ShieldAlert,
  deny: XCircle,
};
