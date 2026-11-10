import type { Rule } from "@mws-dashboard/ui";
import {
  AddLayerVersionPermission as LayerPermission,
  AddPermission,
  CreateAlias,
  CreateEventSourceMapping as Esm,
  CreateFunction,
  PublishLayerVersion,
  PutFunctionConcurrency,
  PutFunctionEventInvokeConfig as Async,
  PutProvisionedConcurrencyConfig,
  UpdateFunctionConfiguration as Update,
} from "@mws-dashboard/ui/model/lambda";

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


export const DESCRIPTION: Rule = Update.Description;
export const EPHEMERAL: Rule = { ...Update.EphemeralStorage.fields!.Size, required: false };
export const DLQ_TARGET: Rule = { ...Update.DeadLetterConfig.fields!.TargetArn, format: "arn", hint: "An SQS queue or SNS topic ARN" };
export const LAYER_ARNS: Rule = { format: "list", hint: "Layer version ARNs, one per line" };

export const ESM = {
  source: { ...Esm.EventSourceArn, required: true, format: "arn", hint: "A queue or stream ARN" } as Rule,
  batch: Esm.BatchSize,
  window: { ...Esm.MaximumBatchingWindowInSeconds, unit: "seconds" } as Rule,
  filter: { ...Esm.FilterCriteria.fields!.Filters.item!.fields!.Pattern, format: "eventPattern" } as Rule,
};

export const STATEMENT_ID: Rule = { ...AddPermission.StatementId, generate: "name" };
export const PRINCIPAL: Rule = { ...AddPermission.Principal, hint: "A service principal, account ID, ARN or *" };
export const PERMISSION_ACTION: Rule = AddPermission.Action;
export const SOURCE_ARN: Rule = { ...AddPermission.SourceArn, format: "arn" };
export const SOURCE_ACCOUNT: Rule = AddPermission.SourceAccount;

export const ALIAS_NAME: Rule = { ...CreateAlias.Name, hint: "Letters, digits, - and _, not only digits", generate: "name" };
export const ALIAS_DESCRIPTION: Rule = CreateAlias.Description;
export const WEIGHT: Rule = { type: "integer", min: 0, max: 100, hint: "Percent of traffic" };

export const RETRIES: Rule = Async.MaximumRetryAttempts;
export const EVENT_AGE: Rule = { ...Async.MaximumEventAgeInSeconds, unit: "seconds" };
export const DESTINATION: Rule = { ...Async.DestinationConfig.fields!.OnSuccess.fields!.Destination, format: "arn", hint: "SQS, SNS, Lambda or EventBridge bus ARN" };

export const RESERVED: Rule = { ...PutFunctionConcurrency.ReservedConcurrentExecutions, required: false };
export const PROVISIONED: Rule = PutProvisionedConcurrencyConfig.ProvisionedConcurrentExecutions;

export const LAYER_NAME: Rule = { ...PublishLayerVersion.LayerName, pattern: "^[a-zA-Z0-9-_]{1,140}$", hint: "Letters, digits, - and _", generate: "name" };
export const LAYER_DESCRIPTION: Rule = PublishLayerVersion.Description;


export const LAYER_PRINCIPAL: Rule = { ...LayerPermission.Principal, hint: "An account ID, or * for everyone" };
export const LAYER_STATEMENT: Rule = { ...LayerPermission.StatementId, generate: "name" };
export const ORG_ID: Rule = LayerPermission.OrganizationId;
