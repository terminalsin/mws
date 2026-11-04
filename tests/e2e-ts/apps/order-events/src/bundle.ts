// Builds the deployment package for a Lambda function: one bundled CommonJS
// file (index.js) zipped in memory.
import { build } from "esbuild";
import { zipSync } from "fflate";

export async function bundleFunction(entryPoint: string): Promise<Uint8Array> {
  const result = await build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "cjs",
    minify: true,
    write: false,
    outfile: "index.js",
  });
  return zipSync({ "index.js": result.outputFiles[0]!.contents });
}
