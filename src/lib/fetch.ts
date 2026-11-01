/** Injectable fetch so tests never hit the network. Shared by the worker and the web app's one egress (ADR 0001). */
export type FetchFn = typeof fetch;
