import { endpoint } from "@mws-dashboard/aws";

export const dynamic = "force-dynamic";

/** Download MWS's state document (`GET /_mws/state`). */
export async function GET() {
  const response = await fetch(`${endpoint()}/_mws/state`, { cache: "no-store" });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return new Response(response.body, {
    status: response.status,
    headers: {
      "content-type": "application/json",
      "content-disposition": `attachment; filename="mws-state-${stamp}.json"`,
    },
  });
}
