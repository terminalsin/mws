import type { Rule } from "@mws-dashboard/ui";
import { CreateApiDestination, CreateArchive, CreateConnection, CreateEventBus, PutEvents, PutRule, PutTargets, StartReplay, UpdateEventBus } from "@mws-dashboard/ui/model/eventbridge";

export const ENTRY = PutEvents.Entries.item!.fields!;
const TARGET_FIELDS = PutTargets.Targets.item!.fields!;
// A target is optional on a new rule: it can get one later.
export const TARGET: Rule = { ...TARGET_FIELDS.Arn, required: false };
export const TARGET_ARN: Rule = { ...TARGET_FIELDS.Arn, format: "arn" };
export const TARGET_ID: Rule = { ...TARGET_FIELDS.Id, generate: "name" };
export const INPUT: Rule = { ...TARGET_FIELDS.Input, format: "json" };
export const INPUT_PATH: Rule = TARGET_FIELDS.InputPath;
export const INPUT_TEMPLATE: Rule = TARGET_FIELDS.InputTransformer.fields!.InputTemplate;
export const INPUT_PATHS: Rule = { format: "json", hint: '{"id": "$.detail.id"}' };
export const RETRIES: Rule = TARGET_FIELDS.RetryPolicy.fields!.MaximumRetryAttempts;
export const EVENT_AGE: Rule = { ...TARGET_FIELDS.RetryPolicy.fields!.MaximumEventAgeInSeconds, unit: "seconds" };
export const DLQ: Rule = { ...TARGET_FIELDS.DeadLetterConfig.fields!.Arn, format: "arn", hint: "An SQS queue ARN" };
export const ROLE: Rule = { ...TARGET_FIELDS.RoleArn, format: "arn", hint: "A role ARN" };
export const GROUP_ID: Rule = TARGET_FIELDS.SqsParameters.fields!.MessageGroupId;
// Sources under aws. belong to AWS services; PutEvents refuses them.
export const SOURCE: Rule = { ...ENTRY.Source, reserved: ["aws."] };
// The model allows "/" for partner buses only; custom buses can't use aws.
export const BUS_NAME: Rule = {
  ...CreateEventBus.Name,
  pattern: "^[.\\-_A-Za-z0-9]+$",
  reserved: ["aws."],
  hint: "Letters, digits, . - and _",
  generate: "name",
};
export const BUS_DESCRIPTION: Rule = UpdateEventBus.Description;
export const RULE_NAME: Rule = { ...PutRule.Name, hint: "Letters, digits, . - and _", generate: "name" };
export const RULE_DESCRIPTION: Rule = PutRule.Description;
export const PATTERN: Rule = PutRule.EventPattern;
export const SCHEDULE: Rule = PutRule.ScheduleExpression;

export const ARCHIVE_NAME: Rule = { ...CreateArchive.ArchiveName, hint: "Letters, digits, . - and _", generate: "name" };
export const ARCHIVE_DESCRIPTION: Rule = CreateArchive.Description;
export const RETENTION: Rule = { ...CreateArchive.RetentionDays, hint: "Days; 0 or empty keeps events forever" };
export const REPLAY_NAME: Rule = { ...StartReplay.ReplayName, hint: "Letters, digits, . - and _", generate: "name" };

export const CONNECTION_NAME: Rule = { ...CreateConnection.Name, hint: "Letters, digits, . - and _", generate: "name" };
const AUTH = CreateConnection.AuthParameters.fields!;
export const API_KEY_NAME: Rule = AUTH.ApiKeyAuthParameters.fields!.ApiKeyName;
export const API_KEY_VALUE: Rule = AUTH.ApiKeyAuthParameters.fields!.ApiKeyValue;
export const USERNAME: Rule = AUTH.BasicAuthParameters.fields!.Username;
export const PASSWORD: Rule = AUTH.BasicAuthParameters.fields!.Password;

export const DESTINATION_NAME: Rule = { ...CreateApiDestination.Name, hint: "Letters, digits, . - and _", generate: "name" };
export const ENDPOINT: Rule = { ...CreateApiDestination.InvocationEndpoint, format: "url" };
export const RATE: Rule = CreateApiDestination.InvocationRateLimitPerSecond;
