// The backend's data layer. It holds only its own IAM user credentials and,
// per request, works with temporary credentials scoped to one tenant, so a
// bug in tenant routing cannot leak another tenant's files: IAM refuses.
import {
  GetObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity } from "@aws-sdk/types";

export interface StorageConfig {
  bucket: string;
  roleArn: string;
  backendCredentials: AwsCredentialIdentity;
}

export class TenantStorage {
  readonly s3: S3Client;

  constructor(
    private readonly config: StorageConfig,
    readonly tenantId: string,
  ) {
    // fromTemporaryCredentials calls sts:AssumeRole as the backend user and
    // refreshes the session before it expires.
    const credentials = fromTemporaryCredentials({
      masterCredentials: config.backendCredentials,
      params: {
        RoleArn: config.roleArn,
        RoleSessionName: `tenant-${tenantId}`,
        Tags: [{ Key: "tenant", Value: tenantId }],
        DurationSeconds: 900,
      },
    });
    this.s3 = new S3Client({ credentials, forcePathStyle: true });
  }

  private key(path: string) {
    return `tenants/${this.tenantId}/${path}`;
  }

  async write(path: string, body: string): Promise<void> {
    await this.s3.send(new PutObjectCommand({ Bucket: this.config.bucket, Key: this.key(path), Body: body }));
  }

  async read(path: string): Promise<string> {
    const { Body } = await this.s3.send(new GetObjectCommand({ Bucket: this.config.bucket, Key: this.key(path) }));
    return Body!.transformToString();
  }

  async list(): Promise<string[]> {
    const { Contents = [] } = await this.s3.send(
      new ListObjectsV2Command({ Bucket: this.config.bucket, Prefix: this.key("") }),
    );
    return Contents.map((o) => o.Key!.slice(this.key("").length));
  }
}
