// What a new bucket is for, as tiles over the create form. Each suggests a
// name and the settings that job wants. Plain data: the client form imports it.

export interface BucketPreset {
  id: string;
  label: string;
  icon: string;
  title: string;
  /** The suggested name (made unique). */
  name: string;
  versioning?: boolean;
  lock?: boolean;
}

export const BUCKET_PRESETS: BucketPreset[] = [
  { id: "general", label: "General", icon: "resource/AmazonSimpleStorageServiceBucket", title: "General purpose: defaults that suit most buckets", name: "app-data" },
  { id: "assets", label: "Website assets", icon: "service/AmazonCloudFront", title: "Static files served to browsers", name: "app-assets" },
  { id: "uploads", label: "Uploads", icon: "resource/AmazonSimpleStorageServiceBucketWithObjects", title: "User uploads, with versions kept", name: "app-uploads", versioning: true },
  { id: "logs", label: "Logs", icon: "resource/AmazonCloudWatchLogs", title: "Access, CloudTrail and flow logs", name: "app-logs" },
  { id: "artifacts", label: "Build artifacts", icon: "service/AWSCodeArtifact", title: "Builds, packages and deploy bundles, versioned", name: "app-artifacts", versioning: true },
  { id: "lake", label: "Data lake", icon: "resource/AWSLakeFormationDataLake", title: "Raw and processed data for analytics", name: "app-lake" },
  { id: "backups", label: "Backups", icon: "service/AWSBackup", title: "Database dumps and snapshots, versioned", name: "app-backups", versioning: true },
  { id: "compliance", label: "Compliance", icon: "resource/AmazonSimpleStorageServiceS3ObjectLock", title: "Write once, read many: Object Lock on", name: "app-records", lock: true },
];

/** Common lifecycle rules: each fills the fields it needs; the rest wait under More. */
export interface LifecyclePreset {
  id: string;
  label: string;
  title: string;
  /** An icon id, or a lucide icon name the form maps. */
  icon: string;
  name: string;
  prefix?: string;
  transition?: number;
  storageClass?: string;
  expire?: number;
  noncurrent?: number;
  abort?: number;
}

export const LIFECYCLE_PRESETS: LifecyclePreset[] = [
  { id: "expire", label: "Expire", title: "Delete objects after a while (logs, temp files)", icon: "lucide:timer", name: "expire-logs", prefix: "logs/", expire: 30 },
  { id: "tier", label: "Infrequent access", title: "Move to Standard-IA after 30 days", icon: "resource/AmazonSimpleStorageServiceS3StandardIA", name: "to-standard-ia", transition: 30, storageClass: "STANDARD_IA" },
  { id: "intelligent", label: "Intelligent-Tiering", title: "Let S3 move objects between tiers", icon: "resource/AmazonSimpleStorageServiceS3IntelligentTiering", name: "intelligent-tiering", transition: 1, storageClass: "INTELLIGENT_TIERING" },
  { id: "archive", label: "Archive", title: "Move to Glacier Flexible Retrieval after 90 days", icon: "resource/AmazonSimpleStorageServiceS3GlacierFlexibleRetrieval", name: "archive", transition: 90, storageClass: "GLACIER" },
  { id: "versions", label: "Old versions", title: "Delete noncurrent versions after 30 days", icon: "lucide:history", name: "expire-noncurrent", noncurrent: 30 },
  { id: "uploads", label: "Stale uploads", title: "Abort incomplete multipart uploads after 7 days", icon: "lucide:upload-x", name: "abort-uploads", abort: 7 },
];
