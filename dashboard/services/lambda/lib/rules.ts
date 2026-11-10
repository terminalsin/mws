import type { Rule } from "@mws-dashboard/ui";
import { CreateFunction, UpdateFunctionConfiguration as Update } from "@mws-dashboard/ui/model/lambda";

// The model's FunctionName also takes ARNs and qualifiers; a new function
// takes a bare name of at most 64 characters (Lambda's documented limit).
export const FUNCTION_NAME: Rule = {
  ...CreateFunction.FunctionName,
  pattern: "^[a-zA-Z0-9_-]{1,64}$",
  maxLength: 64,
  hint: "Letters, digits, - and _",
  generate: "name",
};

// The model's ranges cover Lambda Managed Instances; regular functions stop
// at 10,240 MB and 900 seconds.
export const MEMORY: Rule = { ...Update.MemorySize, max: 10240 };
export const TIMEOUT: Rule = { ...Update.Timeout, max: 900 };
export const HANDLER: Rule = { ...Update.Handler, hint: "file.function, no spaces" };

/** Environment variables Lambda sets itself and refuses to take. */
export const RESERVED_ENV = [
  "_HANDLER",
  "_X_AMZN_TRACE_ID",
  "AWS_DEFAULT_REGION",
  "AWS_REGION",
  "AWS_EXECUTION_ENV",
  "AWS_LAMBDA_FUNCTION_NAME",
  "AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
  "AWS_LAMBDA_FUNCTION_VERSION",
  "AWS_LAMBDA_INITIALIZATION_TYPE",
  "AWS_LAMBDA_LOG_GROUP_NAME",
  "AWS_LAMBDA_LOG_STREAM_NAME",
  "AWS_ACCESS_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_LAMBDA_RUNTIME_API",
  "LAMBDA_TASK_ROOT",
  "LAMBDA_RUNTIME_DIR",
];

export const ENVIRONMENT: Rule = {
  format: "env",
  key: { ...Update.Environment.fields!.Variables.key, taken: RESERVED_ENV },
};

export const ROLE: Rule = { ...Update.Role, format: "arn", hint: "A role ARN" };
