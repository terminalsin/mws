import { GetPackageVersionAssetCommand, type PackageFormat } from "@aws-sdk/client-codeartifact";
import { describeError } from "@mws-dashboard/aws";
import type { NextRequest } from "next/server";

import { codeartifact } from "../../../../lib/clients";

export const dynamic = "force-dynamic";

/** Stream one package version asset to the browser as a download. */
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams;
  const asset = q.get("asset") ?? "";
  try {
    const out = await (await codeartifact()).send(
      new GetPackageVersionAssetCommand({
        domain: q.get("domain") ?? "",
        domainOwner: q.get("owner") || undefined,
        repository: q.get("repo") ?? "",
        format: (q.get("format") ?? "") as PackageFormat,
        namespace: q.get("namespace") || undefined,
        package: q.get("package") ?? "",
        packageVersion: q.get("version") ?? "",
        asset,
      }),
    );
    const name = (out.assetName || asset).split("/").pop() || "asset";
    return new Response(out.asset!.transformToWebStream(), {
      headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(name)}` },
    });
  } catch (e) {
    const status = (e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode;
    return new Response(describeError(e), { status: status && status >= 400 ? status : 502, headers: { "content-type": "text/plain; charset=utf-8" } });
  }
}
