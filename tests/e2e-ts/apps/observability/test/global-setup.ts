// Fail fast, with a useful message, when MWS isn't running.
export default async function checkMws(): Promise<void> {
  const endpoint = process.env.AWS_ENDPOINT_URL!;
  try {
    const res = await fetch(new URL("/_mws/health", endpoint));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
  } catch (err) {
    throw new Error(`MWS is not reachable at ${endpoint} (${err}). Start it with \`cargo run -p mws\` or set MWS_ENDPOINT.`);
  }
}
