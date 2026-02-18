export interface CustomHostname {
    id: string;
    hostname: string;
    status: string;
    ssl: {
        status: string;
        method: string;
        type: string;
        validation_records?: Array<{
            txt_name: string;
            txt_value: string;
        }>;
    };
}

interface CFResponse<T> {
    success: boolean;
    errors: Array<{ code: number; message: string }>;
    result: T;
}

export class CloudflareCustomHostnames {
    private apiToken: string;
    private zoneId: string;
    private baseUrl = 'https://api.cloudflare.com/client/v4';

    constructor(apiToken: string, zoneId: string) {
        this.apiToken = apiToken;
        this.zoneId = zoneId;
    }

    private async request<T>(method: string, path: string, body?: unknown): Promise<CFResponse<T>> {
        const res = await fetch(`${this.baseUrl}/zones/${this.zoneId}${path}`, {
            method,
            headers: {
                'Authorization': `Bearer ${this.apiToken}`,
                'Content-Type': 'application/json',
            },
            body: body ? JSON.stringify(body) : undefined,
        });
        return res.json() as Promise<CFResponse<T>>;
    }

    async create(hostname: string): Promise<CFResponse<CustomHostname>> {
        return this.request<CustomHostname>('POST', '/custom_hostnames', {
            hostname,
            ssl: { method: 'http', type: 'dv' },
        });
    }

    async get(hostnameId: string): Promise<CFResponse<CustomHostname>> {
        return this.request<CustomHostname>('GET', `/custom_hostnames/${hostnameId}`);
    }

    async delete(hostnameId: string): Promise<CFResponse<{ id: string }>> {
        return this.request<{ id: string }>('DELETE', `/custom_hostnames/${hostnameId}`);
    }
}
