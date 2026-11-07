import { GetObjectCommand } from "@aws-sdk/client-s3";
import { describeError } from "@mws-dashboard/aws";
import type { NextRequest } from "next/server";

import { s3 } from "../../../lib/s3";

export const dynamic = "force-dynamic";

/** Stream an object to the browser as a download. */
export async function GET(request: NextRequest) {
  const bucket = request.nextUrl.searchParams.get("bucket") ?? "";
  const key = request.nextUrl.searchParams.get("key") ?? "";
  try {
    const out = await (await s3()).send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    const name = key.split("/").pop() || "object";
    return new Response(out.Body!.transformToWebStream(), {
      headers: {
        "content-type": out.ContentType ?? "application/octet-stream",
        ...(out.ContentLength != null ? { "content-length": String(out.ContentLength) } : {}),
        "content-disposition": `${request.nextUrl.searchParams.has("inline") ? "inline" : "attachment"}; filename*=UTF-8''${encodeURIComponent(name)}`,
      },
    });
  } catch (e) {
    return new Response(describeError(e), { status: 404 });
  }
}
