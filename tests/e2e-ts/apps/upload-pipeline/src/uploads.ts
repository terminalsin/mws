// The API side: hand browsers short-lived URLs instead of AWS credentials.
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { randomUUID } from "node:crypto";

// A client just for presigning. By default the SDK adds a CRC32 checksum to
// every PutObject, and when presigning there is no body yet, so the URL
// would carry the checksum of an empty body and S3 would reject the real
// upload with BadDigest. Only computing checksums when an operation
// requires them avoids that.
const presigner = new S3Client({ forcePathStyle: true, requestChecksumCalculation: "WHEN_REQUIRED" });

export interface UploadTicket {
  key: string;
  url: string;
  headers: Record<string, string>;
}

export async function createUploadUrl(bucket: string, fileName: string, contentType: string): Promise<UploadTicket> {
  const key = `uploads/${randomUUID()}/${fileName}`;
  const command = new PutObjectCommand({ Bucket: bucket, Key: key, ContentType: contentType });
  // Signing the Content-Type means the uploader must send exactly that type.
  const url = await getSignedUrl(presigner, command, { expiresIn: 300, signableHeaders: new Set(["content-type"]) });
  return { key, url, headers: { "content-type": contentType } };
}

export async function createDownloadUrl(bucket: string, key: string): Promise<string> {
  return getSignedUrl(presigner, new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn: 300 });
}
