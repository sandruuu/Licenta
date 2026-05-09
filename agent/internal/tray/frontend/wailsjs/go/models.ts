export namespace ipc {
	
	export class AccessEvent {
	    id: string;
	    decision: string;
	    reason: string;
	    source?: string;
	    resource_id?: string;
	    fqdn?: string;
	    protocol?: string;
	    port?: number;
	    details?: Record<string, string>;
	    // Go type: time
	    occurred_at: any;
	
	    static createFrom(source: any = {}) {
	        return new AccessEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.decision = source["decision"];
	        this.reason = source["reason"];
	        this.source = source["source"];
	        this.resource_id = source["resource_id"];
	        this.fqdn = source["fqdn"];
	        this.protocol = source["protocol"];
	        this.port = source["port"];
	        this.details = source["details"];
	        this.occurred_at = this.convertValues(source["occurred_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AccessEventsResponse {
	    events: AccessEvent[];
	    // Go type: time
	    reported_at: any;
	
	    static createFrom(source: any = {}) {
	        return new AccessEventsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.events = this.convertValues(source["events"], AccessEvent);
	        this.reported_at = this.convertValues(source["reported_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ActiveSession {
	    id: string;
	    resource_id?: string;
	    fqdn?: string;
	    protocol?: string;
	    port?: number;
	    state: string;
	    user_sid?: string;
	    // Go type: time
	    started_at?: any;
	    // Go type: time
	    expires_at?: any;
	    bytes_in?: number;
	    bytes_out?: number;
	    last_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ActiveSession(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.resource_id = source["resource_id"];
	        this.fqdn = source["fqdn"];
	        this.protocol = source["protocol"];
	        this.port = source["port"];
	        this.state = source["state"];
	        this.user_sid = source["user_sid"];
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.expires_at = this.convertValues(source["expires_at"], null);
	        this.bytes_in = source["bytes_in"];
	        this.bytes_out = source["bytes_out"];
	        this.last_error = source["last_error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ActiveSessionsResponse {
	    sessions: ActiveSession[];
	    // Go type: time
	    reported_at: any;
	
	    static createFrom(source: any = {}) {
	        return new ActiveSessionsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sessions = this.convertValues(source["sessions"], ActiveSession);
	        this.reported_at = this.convertValues(source["reported_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CatalogResource {
	    fqdn: string;
	    resource_id?: string;
	    protocol?: string;
	    port?: number;
	    status?: string;
	    // Go type: time
	    updated_at?: any;
	
	    static createFrom(source: any = {}) {
	        return new CatalogResource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fqdn = source["fqdn"];
	        this.resource_id = source["resource_id"];
	        this.protocol = source["protocol"];
	        this.port = source["port"];
	        this.status = source["status"];
	        this.updated_at = this.convertValues(source["updated_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DevicePostureCheck {
	    name: string;
	    status: string;
	    description: string;
	    details?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new DevicePostureCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.description = source["description"];
	        this.details = source["details"];
	    }
	}
	export class DevicePostureReport {
	    device_id?: string;
	    hostname: string;
	    os: string;
	    checks: DevicePostureCheck[];
	    // Go type: time
	    collected_at: any;
	
	    static createFrom(source: any = {}) {
	        return new DevicePostureReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_id = source["device_id"];
	        this.hostname = source["hostname"];
	        this.os = source["os"];
	        this.checks = this.convertValues(source["checks"], DevicePostureCheck);
	        this.collected_at = this.convertValues(source["collected_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AuthenticatedUser {
	    user_sid?: string;
	    authorized_user_sid?: string;
	    email?: string;
	    session_state?: string;
	    // Go type: time
	    access_token_expires_at?: any;
	
	    static createFrom(source: any = {}) {
	        return new AuthenticatedUser(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.user_sid = source["user_sid"];
	        this.authorized_user_sid = source["authorized_user_sid"];
	        this.email = source["email"];
	        this.session_state = source["session_state"];
	        this.access_token_expires_at = this.convertValues(source["access_token_expires_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CertificateInfo {
	    sha256?: string;
	    subject?: string;
	    issuer?: string;
	    serial_number?: string;
	    // Go type: time
	    not_before?: any;
	    // Go type: time
	    expires_at?: any;
	    valid: boolean;
	    last_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new CertificateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sha256 = source["sha256"];
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.serial_number = source["serial_number"];
	        this.not_before = this.convertValues(source["not_before"], null);
	        this.expires_at = this.convertValues(source["expires_at"], null);
	        this.valid = source["valid"];
	        this.last_error = source["last_error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class EnrollmentInfo {
	    state: string;
	    device_id?: string;
	    device_id_source?: string;
	    active_user_sid?: string;
	    key_name?: string;
	    key_exists: boolean;
	    key_provider?: string;
	    nonce?: string;
	    last_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new EnrollmentInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.device_id = source["device_id"];
	        this.device_id_source = source["device_id_source"];
	        this.active_user_sid = source["active_user_sid"];
	        this.key_name = source["key_name"];
	        this.key_exists = source["key_exists"];
	        this.key_provider = source["key_provider"];
	        this.nonce = source["nonce"];
	        this.last_error = source["last_error"];
	    }
	}
	export class AgentStatus {
	    service_state: string;
	    service_pid: number;
	    service_user?: string;
	    service_user_sid?: string;
	    authorized_user_sid?: string;
	    enrollment_state: string;
	    device_id?: string;
	    device_id_source?: string;
	    active_user_sid?: string;
	    key_name?: string;
	    key_exists: boolean;
	    key_provider?: string;
	    enrollment_nonce?: string;
	    certificate_sha256?: string;
	    // Go type: time
	    certificate_expires_at?: any;
	    device_posture_status?: string;
	    device_posture_check_count?: number;
	    // Go type: time
	    device_posture_collected_at?: any;
	    // Go type: time
	    device_posture_reported_at?: any;
	    device_posture_last_error?: string;
	    device_posture_report_error?: string;
	    session_state?: string;
	    // Go type: time
	    access_token_expires_at?: any;
	    catalog_status?: string;
	    catalog_version?: string;
	    catalog_policy_epoch?: string;
	    catalog_dns_suffix_count?: number;
	    catalog_resource_count?: number;
	    // Go type: time
	    catalog_last_synced_at?: any;
	    // Go type: time
	    catalog_next_sync_at?: any;
	    // Go type: time
	    catalog_next_retry_at?: any;
	    catalog_last_error?: string;
	    synthetic_dns_status?: string;
	    synthetic_dns_suffix_count?: number;
	    synthetic_resource_count?: number;
	    synthetic_mapping_count?: number;
	    synthetic_cgnat_range?: string;
	    // Go type: time
	    synthetic_dns_updated_at?: any;
	    synthetic_dns_last_error?: string;
	    network_status?: string;
	    tun_name?: string;
	    tun_ip?: string;
	    tun_netmask?: string;
	    tun_route_cidr?: string;
	    // Go type: time
	    network_updated_at?: any;
	    network_packets_read?: number;
	    network_tcp_packets?: number;
	    network_matched_packets?: number;
	    network_unmatched_packets?: number;
	    network_dropped_packets?: number;
	    network_forwarder_ready: boolean;
	    // Go type: time
	    network_last_packet_at?: any;
	    network_last_packet_error?: string;
	    network_last_error?: string;
	    gateway_tunnel_status?: string;
	    gateway_address?: string;
	    // Go type: time
	    gateway_tunnel_connected_at?: any;
	    // Go type: time
	    gateway_tunnel_updated_at?: any;
	    gateway_tunnel_last_error?: string;
	    gateway_tunnel_stream_count?: number;
	    last_error?: string;
	    identity_error?: string;
	    // Go type: time
	    identity_checked_at?: any;
	    // Go type: time
	    reported_at: any;
	
	    static createFrom(source: any = {}) {
	        return new AgentStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service_state = source["service_state"];
	        this.service_pid = source["service_pid"];
	        this.service_user = source["service_user"];
	        this.service_user_sid = source["service_user_sid"];
	        this.authorized_user_sid = source["authorized_user_sid"];
	        this.enrollment_state = source["enrollment_state"];
	        this.device_id = source["device_id"];
	        this.device_id_source = source["device_id_source"];
	        this.active_user_sid = source["active_user_sid"];
	        this.key_name = source["key_name"];
	        this.key_exists = source["key_exists"];
	        this.key_provider = source["key_provider"];
	        this.enrollment_nonce = source["enrollment_nonce"];
	        this.certificate_sha256 = source["certificate_sha256"];
	        this.certificate_expires_at = this.convertValues(source["certificate_expires_at"], null);
	        this.device_posture_status = source["device_posture_status"];
	        this.device_posture_check_count = source["device_posture_check_count"];
	        this.device_posture_collected_at = this.convertValues(source["device_posture_collected_at"], null);
	        this.device_posture_reported_at = this.convertValues(source["device_posture_reported_at"], null);
	        this.device_posture_last_error = source["device_posture_last_error"];
	        this.device_posture_report_error = source["device_posture_report_error"];
	        this.session_state = source["session_state"];
	        this.access_token_expires_at = this.convertValues(source["access_token_expires_at"], null);
	        this.catalog_status = source["catalog_status"];
	        this.catalog_version = source["catalog_version"];
	        this.catalog_policy_epoch = source["catalog_policy_epoch"];
	        this.catalog_dns_suffix_count = source["catalog_dns_suffix_count"];
	        this.catalog_resource_count = source["catalog_resource_count"];
	        this.catalog_last_synced_at = this.convertValues(source["catalog_last_synced_at"], null);
	        this.catalog_next_sync_at = this.convertValues(source["catalog_next_sync_at"], null);
	        this.catalog_next_retry_at = this.convertValues(source["catalog_next_retry_at"], null);
	        this.catalog_last_error = source["catalog_last_error"];
	        this.synthetic_dns_status = source["synthetic_dns_status"];
	        this.synthetic_dns_suffix_count = source["synthetic_dns_suffix_count"];
	        this.synthetic_resource_count = source["synthetic_resource_count"];
	        this.synthetic_mapping_count = source["synthetic_mapping_count"];
	        this.synthetic_cgnat_range = source["synthetic_cgnat_range"];
	        this.synthetic_dns_updated_at = this.convertValues(source["synthetic_dns_updated_at"], null);
	        this.synthetic_dns_last_error = source["synthetic_dns_last_error"];
	        this.network_status = source["network_status"];
	        this.tun_name = source["tun_name"];
	        this.tun_ip = source["tun_ip"];
	        this.tun_netmask = source["tun_netmask"];
	        this.tun_route_cidr = source["tun_route_cidr"];
	        this.network_updated_at = this.convertValues(source["network_updated_at"], null);
	        this.network_packets_read = source["network_packets_read"];
	        this.network_tcp_packets = source["network_tcp_packets"];
	        this.network_matched_packets = source["network_matched_packets"];
	        this.network_unmatched_packets = source["network_unmatched_packets"];
	        this.network_dropped_packets = source["network_dropped_packets"];
	        this.network_forwarder_ready = source["network_forwarder_ready"];
	        this.network_last_packet_at = this.convertValues(source["network_last_packet_at"], null);
	        this.network_last_packet_error = source["network_last_packet_error"];
	        this.network_last_error = source["network_last_error"];
	        this.gateway_tunnel_status = source["gateway_tunnel_status"];
	        this.gateway_address = source["gateway_address"];
	        this.gateway_tunnel_connected_at = this.convertValues(source["gateway_tunnel_connected_at"], null);
	        this.gateway_tunnel_updated_at = this.convertValues(source["gateway_tunnel_updated_at"], null);
	        this.gateway_tunnel_last_error = source["gateway_tunnel_last_error"];
	        this.gateway_tunnel_stream_count = source["gateway_tunnel_stream_count"];
	        this.last_error = source["last_error"];
	        this.identity_error = source["identity_error"];
	        this.identity_checked_at = this.convertValues(source["identity_checked_at"], null);
	        this.reported_at = this.convertValues(source["reported_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DashboardConnection {
	    state: string;
	    message?: string;
	    service_state?: string;
	    session_state?: string;
	    catalog_state?: string;
	    network_state?: string;
	
	    static createFrom(source: any = {}) {
	        return new DashboardConnection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.message = source["message"];
	        this.service_state = source["service_state"];
	        this.session_state = source["session_state"];
	        this.catalog_state = source["catalog_state"];
	        this.network_state = source["network_state"];
	    }
	}
	export class AgentDashboard {
	    connection: DashboardConnection;
	    status: AgentStatus;
	    enrollment: EnrollmentInfo;
	    certificate: CertificateInfo;
	    user: AuthenticatedUser;
	    posture: DevicePostureReport;
	    resources: CatalogResource[];
	    active_sessions: ActiveSession[];
	    access_events: AccessEvent[];
	    // Go type: time
	    reported_at: any;
	
	    static createFrom(source: any = {}) {
	        return new AgentDashboard(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connection = this.convertValues(source["connection"], DashboardConnection);
	        this.status = this.convertValues(source["status"], AgentStatus);
	        this.enrollment = this.convertValues(source["enrollment"], EnrollmentInfo);
	        this.certificate = this.convertValues(source["certificate"], CertificateInfo);
	        this.user = this.convertValues(source["user"], AuthenticatedUser);
	        this.posture = this.convertValues(source["posture"], DevicePostureReport);
	        this.resources = this.convertValues(source["resources"], CatalogResource);
	        this.active_sessions = this.convertValues(source["active_sessions"], ActiveSession);
	        this.access_events = this.convertValues(source["access_events"], AccessEvent);
	        this.reported_at = this.convertValues(source["reported_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class CatalogResourcesResponse {
	    resources: CatalogResource[];
	    // Go type: time
	    reported_at: any;
	
	    static createFrom(source: any = {}) {
	        return new CatalogResourcesResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resources = this.convertValues(source["resources"], CatalogResource);
	        this.reported_at = this.convertValues(source["reported_at"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	

}

