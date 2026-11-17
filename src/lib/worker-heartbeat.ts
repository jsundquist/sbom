/** `feed_syncs` row the worker stamps after an enrichment run with no job errors; /metrics reads it. Shared because worker and server may not import each other. */
export const WORKER_FEED = 'worker';
