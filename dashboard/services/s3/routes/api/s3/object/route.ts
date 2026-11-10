import { GetObjectCommand } from "@aws-sdk/client-s3";
import { describeError } from "@mws-dashboard/aws";
import type { NextRequest } from "next/server";

import { s3 } from "../../../../lib/s3";

export const dynamic = "force-dynamic";

/** Stream an object (or one version of it) to the browser as a download. */
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams;
  const bucket = q.get("bucket") ?? "";
  const key = q.get("key") ?? "";
  try {
    const out = await (await s3()).send(new GetObjectCommand({ Bucket: bucket, Key: key, VersionId: q.get("version") || undefined }));
    const name = key.split("/").pop() || "object";
    return new Response(out.Body!.transformToWebStream(), {
      headers: {
        "content-type": out.ContentType ?? "application/octet-stream",
        ...(out.ContentLength != null ? { "content-length": String(out.ContentLength) } : {}),
        "content-disposition": `${q.has("inline") ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(name)}`,
      },
    });
  } catch (e) {
    // Keep S3's status: 403 for AccessDenied or KMS denials, 404 for a missing key, 400 for a bad version id.
    const status = (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    return new Response(describeError(e), { status: status && status >= 400 ? status : 502, headers: { "content-type": "text/plain; charset=utf-8" } });
  }
}
