export namespace main {
	
	export class CloudReporter {
	
	
	    static createFrom(source: any = {}) {
	        return new CloudReporter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}
	export class HealthCheck {
	    name: string;
	    status: string;
	    description: string;
	    details: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new HealthCheck(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.description = source["description"];
	        this.details = source["details"];
	    }
	}
	export class DeviceHealth {
	    hostname: string;
	    os: string;
	    checks: HealthCheck[];
	    overallScore: number;
	    collectedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new DeviceHealth(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hostname = source["hostname"];
	        this.os = source["os"];
	        this.checks = this.convertValues(source["checks"], HealthCheck);
	        this.overallScore = source["overallScore"];
	        this.collectedAt = source["collectedAt"];
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

