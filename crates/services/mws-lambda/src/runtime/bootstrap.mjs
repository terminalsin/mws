// MWS's Node.js runtime client: the Lambda Runtime API loop around a
// handler, reporting errors in the shapes the AWS Node.js runtime uses.

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import util from "node:util";

const [host, port] = process.env.AWS_LAMBDA_RUNTIME_API.split(":");
const BASE = "/2018-06-01/runtime";
let requestId = "";

function call(method, p, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, method, path: BASE + p, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

for (const [name, level] of [["log", "INFO"], ["info", "INFO"], ["warn", "WARN"], ["error", "ERROR"], ["debug", "DEBUG"]]) {
  console[name] = (...args) => {
    process.stdout.write(`${new Date().toISOString()}\t${requestId || "undefined"}\t${level}\t${util.format(...args)}\n`);
  };
}

function errorPayload(e) {
  if (e instanceof Error) {
    return { errorType: e.name, errorMessage: e.message, trace: (e.stack || "").split("\n") };
  }
  return { errorType: typeof e, errorMessage: String(e), trace: [] };
}

async function initError(errorType, errorMessage) {
  process.stderr.write(`${errorType}: ${errorMessage}\n`);
  await call("POST", "/init/error", JSON.stringify({ errorType, errorMessage, trace: [] }), {
    "Lambda-Runtime-Function-Error-Type": errorType,
  });
  process.exit(1);
}

async function loadHandler() {
  const handler = process.env._HANDLER || "";
  const dot = handler.lastIndexOf(".");
  if (dot <= 0) await initError("Runtime.MalformedHandlerName", `Bad handler ${handler}`);
  const modulePath = handler.slice(0, dot);
  const fnName = handler.slice(dot + 1);
  const root = process.env.LAMBDA_TASK_ROOT || process.cwd();
  const file = [".js", ".mjs", ".cjs"].map((ext) => path.join(root, modulePath + ext)).find((f) => fs.existsSync(f));
  if (!file) {
    await initError("Runtime.ImportModuleError", `Error: Cannot find module '${modulePath}'`);
  }
  let mod;
  try {
    mod = await import(pathToFileURL(file).href);
  } catch (e) {
    await initError(e instanceof SyntaxError ? "Runtime.UserCodeSyntaxError" : "Runtime.ImportModuleError", String(e));
  }
  const fn = mod[fnName] ?? mod.default?.[fnName];
  if (typeof fn !== "function") {
    await initError("Runtime.HandlerNotFound", `${handler} is undefined or not exported`);
  }
  return fn;
}

const fn = await loadHandler();
for (;;) {
  const next = await call("GET", "/invocation/next");
  const h = next.headers;
  requestId = h["lambda-runtime-aws-request-id"];
  process.env._X_AMZN_TRACE_ID = h["lambda-runtime-trace-id"] || "";
  const deadline = Number(h["lambda-runtime-deadline-ms"] || 0);
  const context = {
    awsRequestId: requestId,
    functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
    functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
    invokedFunctionArn: h["lambda-runtime-invoked-function-arn"],
    memoryLimitInMB: process.env.AWS_LAMBDA_FUNCTION_MEMORY_SIZE,
    logGroupName: process.env.AWS_LAMBDA_LOG_GROUP_NAME,
    logStreamName: process.env.AWS_LAMBDA_LOG_STREAM_NAME,
    clientContext: h["lambda-runtime-client-context"] ? JSON.parse(h["lambda-runtime-client-context"]) : undefined,
    identity: h["lambda-runtime-cognito-identity"] ? JSON.parse(h["lambda-runtime-cognito-identity"]) : undefined,
    callbackWaitsForEmptyEventLoop: true,
    getRemainingTimeInMillis: () => Math.max(0, deadline - Date.now()),
  };
  try {
    const event = next.body.length ? JSON.parse(next.body.toString("utf8")) : null;
    let result;
    if (fn.length >= 3) {
      result = await new Promise((resolve, reject) => {
        const r = fn(event, context, (err, value) => (err ? reject(err) : resolve(value)));
        if (r && typeof r.then === "function") r.then(resolve, reject);
      });
    } else {
      result = await fn(event, context);
    }
    await call("POST", `/invocation/${requestId}/response`, JSON.stringify(result === undefined ? null : result));
  } catch (e) {
    const payload = errorPayload(e);
    process.stderr.write(`${new Date().toISOString()}\t${requestId}\tERROR\tInvoke Error \t${JSON.stringify(payload)}\n`);
    await call("POST", `/invocation/${requestId}/error`, JSON.stringify(payload), {
      "Lambda-Runtime-Function-Error-Type": "Unhandled",
      "Content-Type": "application/json",
    });
  }
}
