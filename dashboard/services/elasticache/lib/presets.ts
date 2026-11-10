// The create sheet's tiles: the engine, then how it runs. Plain data, so
// both the server page and the client form can import it.

export interface EnginePreset {
  id: "valkey" | "redis" | "memcached";
  label: string;
  icon: string;
  title?: string;
}

export const ENGINE_PRESETS: EnginePreset[] = [
  { id: "valkey", label: "Valkey", icon: "resource/AmazonElastiCacheElastiCacheforValkey", title: "Valkey: Redis OSS compatible, lower cost" },
  { id: "redis", label: "Redis OSS", icon: "brand/redis" },
  { id: "memcached", label: "Memcached", icon: "resource/AmazonElastiCacheElastiCacheforMemcached" },
];

export interface ModePreset {
  id: "serverless" | "nodes";
  label: string;
  title: string;
}

export const MODE_PRESETS: ModePreset[] = [
  { id: "serverless", label: "Serverless", title: "Scales by itself; nothing to size" },
  { id: "nodes", label: "Nodes", title: "Design your own cache: node type, count and shards" },
];
