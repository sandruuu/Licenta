export namespace ipc {

	export class AgentDashboard {
	    connection: DashboardConnection;
	    status: AgentStatus;
	    enrollment: EnrollmentInfo;
	    device_data: DeviceDataReport;
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
	        this.device_data = this.convertValues(source["device_data"], DeviceDataReport);
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
	export class AgentStatus {
	    service_state: string;
	    service_pid: number;
	    service_user?: string;
	    service_user_sid?: string;
	    enrollment_state: string;
	    enrollment_device_id?: string;
	    enrollment_last_error?: string;
	    device_data_status?: string;
	    device_data_check_count?: number;
	    // Go type: time
	    device_data_collected_at?: any;
	    device_data_last_error?: string;
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
	        this.enrollment_state = source["enrollment_state"];
	        this.enrollment_device_id = source["enrollment_device_id"];
	        this.enrollment_last_error = source["enrollment_last_error"];
	        this.device_data_status = source["device_data_status"];
	        this.device_data_check_count = source["device_data_check_count"];
	        this.device_data_collected_at = this.convertValues(source["device_data_collected_at"], null);
	        this.device_data_last_error = source["device_data_last_error"];
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

	    static createFrom(source: any = {}) {
	        return new DashboardConnection(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.message = source["message"];
	        this.service_state = source["service_state"];
	    }
	}
	export class DeviceDataCheck {
	    name: string;
	    status: string;
	    description: string;
	    details?: Record<string, string>;

	    static createFrom(source: any = {}) {
	        return new DeviceDataCheck(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.description = source["description"];
	        this.details = source["details"];
	    }
	}
	export class DeviceDataReport {
	    device_id?: string;
	    hostname: string;
	    os: string;
	    checks: DeviceDataCheck[];
	    // Go type: time
	    collected_at: any;

	    static createFrom(source: any = {}) {
	        return new DeviceDataReport(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_id = source["device_id"];
	        this.hostname = source["hostname"];
	        this.os = source["os"];
	        this.checks = this.convertValues(source["checks"], DeviceDataCheck);
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
	export class EnrollmentInfo {
	    state: string;
	    device_id?: string;
	    message?: string;
	    last_error?: string;

	    static createFrom(source: any = {}) {
	        return new EnrollmentInfo(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.device_id = source["device_id"];
	        this.message = source["message"];
	        this.last_error = source["last_error"];
	    }
	}
	export class StartEnrollmentInteractiveResponse {
	    started: boolean;
	    auth_url?: string;
	    enrollment_session_id?: string;
	    state: string;
	    message?: string;
	    // Go type: time
	    expires_at?: any;
	    poll_interval_seconds?: number;
	    // Go type: time
	    reported_at: any;

	    static createFrom(source: any = {}) {
	        return new StartEnrollmentInteractiveResponse(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.started = source["started"];
	        this.auth_url = source["auth_url"];
	        this.enrollment_session_id = source["enrollment_session_id"];
	        this.state = source["state"];
	        this.message = source["message"];
	        this.expires_at = this.convertValues(source["expires_at"], null);
	        this.poll_interval_seconds = source["poll_interval_seconds"];
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

