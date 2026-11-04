import { defineConfig } from "vitest/config";

// The app code never mentions MWS: the AWS SDK reads AWS_ENDPOINT_URL,
// AWS_REGION and the credential variables from the environment, exactly as
// it does when deployed. The tests point those at MWS (by default a local
// `cargo run -p mws` and its root user) and override whatever AWS settings
// the shell has, so a test run can never reach a real AWS account.
const env = {
  AWS_ENDPOINT_URL: process.env.MWS_ENDPOINT ?? "http://127.0.0.1:4566",
  AWS_REGION: process.env.MWS_REGION ?? "us-east-1",
  AWS_ACCESS_KEY_ID: process.env.MWS_ROOT_ACCESS_KEY_ID ?? "AKIAMWSROOTEXAMPLE00",
  AWS_SECRET_ACCESS_KEY: process.env.MWS_ROOT_SECRET_ACCESS_KEY ?? "mwsRootSecretAccessKeyEXAMPLEKEY00000000",
};
for (const name of ["AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"]) delete process.env[name];
Object.assign(process.env, env);

export default defineConfig({
  test: {
    env,
    globalSetup: ["./test/global-setup.ts"],
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
