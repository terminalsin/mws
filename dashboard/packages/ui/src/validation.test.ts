import assert from "node:assert/strict";
import { test } from "node:test";

import { check, closest, describePattern, fresh, parseServerIssues, repairJson, ruleAt, sameMember, valid, type Rule } from "./validation.ts";

const values = (r: Rule, v: string) => check(v, r)?.repairs.map((x) => x.value) ?? [];

test("valid values have no issue", () => {
  assert.equal(check("orders", { pattern: "^[a-z]+$", maxLength: 10 }), null);
  assert.equal(check("", { pattern: "^[a-z]+$" }), null);
});

test("required fields offer a generated value", () => {
  const rule: Rule = { required: true, pattern: "^[a-z0-9-]+$", maxLength: 30, generate: "name" };
  const issue = check("", rule)!;
  assert.equal(issue.code, "required");
  assert.equal(issue.repairs[0].kind, "generate");
  assert.ok(valid(issue.repairs[0].value, rule));
});

test("pattern mismatches are reshaped to fit", () => {
  const rule: Rule = { pattern: "^[a-z0-9-]+$" };
  assert.deepEqual(values(rule, "My Queue"), ["my-queue"]);
  assert.deepEqual(values({ pattern: "^[a-zA-Z0-9_-]+$" }, " orders "), ["orders"]);
  assert.deepEqual(values({ pattern: "^[a-zA-Z0-9_-]+$" }, "orders.v2!"), ["orders-v2"]);
  assert.deepEqual(values({ pattern: "^[a-zA-Z0-9_-]{1,75}\\.fifo$" }, "jobs"), ["jobs.fifo"]);
  assert.deepEqual(values({ pattern: "^[a-zA-Z0-9_-]{1,75}\\.fifo$" }, "my jobs"), ["my-jobs.fifo"]);
  assert.deepEqual(values({ pattern: "^[A-Za-z0-9_-]{1,80}$|^[A-Za-z0-9_-]{1,75}\\.fifo$" }, "Orders Queue (prod)"), ["Orders-Queue-prod"]);
});

test("identifiers that must start with a letter drop what comes first", () => {
  const rule: Rule = { pattern: "^[a-zA-Z](?!.*--)[a-zA-Z0-9-]*(?<!-)$" };
  assert.deepEqual(values(rule, "1cache"), ["cache"]);
  assert.deepEqual(values(rule, "2 my cache"), ["my-cache"]);
  assert.equal(check("1cache", rule)!.repairs[0].label, "Start with a letter");
  assert.deepEqual(values(rule, "my--cache-"), ["my-cache"]);
});

test("too long values are shortened", () => {
  assert.deepEqual(values({ maxLength: 5 }, "abcdefgh"), ["abcde"]);
});

test("enums suggest close matches", () => {
  const rule: Rule = { enum: ["STANDARD", "EXPRESS"] };
  assert.deepEqual(values(rule, "standard"), ["STANDARD"]);
  assert.deepEqual(values(rule, "EXPRES"), ["EXPRESS"]);
  assert.deepEqual(values({ enum: ["us-east-1", "eu-west-1"] }, "us east 1"), ["us-east-1"]);
});

test("numbers are parsed and clamped", () => {
  assert.deepEqual(values({ type: "integer", min: 1, max: 1000 }, "5000"), ["1000"]);
  assert.deepEqual(values({ type: "integer", min: 1, max: 1000 }, "30s"), ["30"]);
  assert.deepEqual(values({ type: "integer" }, "1,200"), ["1200"]);
});

test("taken names get the next free variant", () => {
  assert.deepEqual(values({ taken: ["orders", "orders-2"] }, "orders"), ["orders-3"]);
  assert.deepEqual(values({ taken: ["jobs.fifo"], pattern: "^[a-z-]+\\d*(\\.fifo)?$" }, "jobs.fifo")[0], "jobs-2.fifo".replace("-2", "-2"));
});

test("formats repair common mistakes", () => {
  assert.deepEqual(values({ format: "cidr" }, "10.0.0.1/16"), ["10.0.0.0/16"]);
  assert.deepEqual(values({ format: "cidr" }, "10.1.2.3"), ["10.1.0.0/16", "10.1.2.0/24"]);
  assert.deepEqual(values({ format: "email" }, "dev@gmial.com"), ["dev@gmail.com"]);
  assert.deepEqual(values({ format: "url" }, "example.com/hook"), ["https://example.com/hook"]);
  assert.deepEqual(values({ format: "arn", arn: "arn:aws:iam::123456789012:role/{}" }, "deployer"), ["arn:aws:iam::123456789012:role/deployer"]);
  assert.deepEqual(values({ format: "bucket" }, "My_Bucket"), ["my-bucket"]);
  assert.equal(check('{"a": 1,}', { format: "json" })?.repairs[0].value, '{\n  "a": 1\n}');
});

test("JSON repair handles hand-written JSON", () => {
  assert.equal(repairJson("{'Version': '2012-10-17', Statement: [],}"), '{\n  "Version": "2012-10-17",\n  "Statement": []\n}');
  assert.equal(repairJson('"a": 1'), '{\n  "a": 1\n}');
  assert.equal(repairJson("not json at all"), null);
});

test("patterns read as text", () => {
  assert.equal(describePattern("^[a-zA-Z0-9_-]+$"), "Letters, digits, _ and -");
  assert.equal(describePattern("^[a-z0-9.-]+$"), "Lowercase letters, digits, . and -");
  assert.equal(describePattern("^[\\w+=,.@-]+$"), "Letters, digits, +, =, ,, ., @, - and _");
});

test("closest ranks normalized, prefix, then edit-distance matches", () => {
  assert.deepEqual(closest("lambda-exec", ["lambda-execution-role", "ecs-task", "LambdaExec"]), ["LambdaExec", "lambda-execution-role"]);
  assert.deepEqual(closest("zzz", ["alpha", "beta"]), []);
});

test("server validation messages become field rules", () => {
  const issues = parseServerIssues(
    "2 validation errors detected: Value 'My Role' at 'roleName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]+; Value null at 'assumeRolePolicyDocument' failed to satisfy constraint: Member must not be null",
  );
  assert.equal(issues.length, 2);
  assert.equal(issues[0].member, "roleName");
  assert.equal(issues[0].value, "My Role");
  assert.equal(issues[0].code, "pattern");
  assert.deepEqual(check("My Role", issues[0].rule!)?.repairs.map((r) => r.value), ["My-Role"]);
  assert.equal(issues[1].code, "required");
  const enumIssue = parseServerIssues("1 validation error detected: Value 'FOO' at 'shardIteratorType' failed to satisfy constraint: Member must satisfy enum value set: [AFTER_SEQUENCE_NUMBER, LATEST]")[0];
  assert.deepEqual(enumIssue.rule?.enum, ["AFTER_SEQUENCE_NUMBER", "LATEST"]);
  assert.equal(parseServerIssues("Value (x y) for parameter QueueName is invalid. Reason: Can only include alphanumeric characters.")[0].member, "QueueName");
  assert.deepEqual(parseServerIssues("Access denied"), []);
});

test("member paths match across protocols", () => {
  assert.ok(sameMember("queueName", "QueueName"));
  assert.ok(sameMember("tags.1.member.key", "Tags.Key"));
  assert.ok(!sameMember("roleName", "path"));
  assert.equal(ruleAt({ VpcConfig: { fields: { SubnetIds: { type: "list", item: { maxLength: 9 } } } } }, "vpcConfig.subnetIds.1")?.maxLength, 9);
});

test("fresh values fit the rule", () => {
  for (const generate of ["name", "token", "password", "uuid", { prefix: "orders-" }] as const) {
    const rule: Rule = { generate, maxLength: 64, minLength: 3 };
    const v = fresh(rule);
    assert.ok(v && valid(v.value, rule), JSON.stringify(generate));
  }
  const fifo = fresh({ generate: { suffix: ".fifo" }, pattern: "^[a-zA-Z0-9_-]{1,75}\\.fifo$" });
  assert.ok(fifo?.value.endsWith(".fifo"));
});
