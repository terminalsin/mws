// Queue presets: what the console fills in when creating a queue. Shared by
// the server page and the client form (no server-only imports).

export interface QueuePreset {
  id: string;
  label: string;
  title: string;
  /** The name it suggests (made unique against the existing queues). */
  name: string;
  fifo: boolean;
  dedup?: boolean;
  VisibilityTimeout?: string;
  MessageRetentionPeriod?: string;
  DelaySeconds?: string;
  ReceiveMessageWaitTimeSeconds?: string;
  /** Only these presets are meant to be someone's dead-letter queue. */
  allow?: string;
}

export const QUEUE_PRESETS: QueuePreset[] = [
  { id: "standard", label: "Standard", title: "At-least-once, best-effort ordering, nearly unlimited throughput", name: "queue", fifo: false },
  { id: "fifo", label: "FIFO", title: "Exactly-once, ordered per message group", name: "queue.fifo", fifo: true, dedup: true },
  { id: "long-poll", label: "Long polling", title: "Receives wait up to 20 s for messages: fewer empty responses", name: "queue", fifo: false, ReceiveMessageWaitTimeSeconds: "20" },
  { id: "delay", label: "Delay queue", title: "Every message stays invisible for a minute after it is sent", name: "delayed", fifo: false, DelaySeconds: "60" },
  { id: "dlq", label: "Dead-letter", title: "Keeps failed messages for 14 days, for any queue to use", name: "dlq", fifo: false, MessageRetentionPeriod: "1209600", allow: "allowAll" },
];
