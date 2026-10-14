export const packageHref = (key: string) => `/packages/${encodeURIComponent(key)}`;
export const vulnHref = (id: string) => `/vulnerabilities/${encodeURIComponent(id)}`;
export const projectHref = (id: number) => `/projects/${id}`;
