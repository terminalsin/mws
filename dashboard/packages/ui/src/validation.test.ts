import assert from "node:assert/strict";
import { test } from "node:test";

import { check, closest, describePattern, fresh, parseServerIssues, repairJson, repairPolicy, ruleAt, sameMember, valid, type Rule } from "./validation.ts";

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
  // Separators side by side or at the ends (CloudTrail trail names).
  const trail: Rule = { pattern: "^[A-Za-z0-9](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9]))*$" };
  assert.deepEqual(values(trail, "my-_trail."), ["my-trail"]);
  assert.deepEqual(values(trail, "_audit  logs"), ["audit-logs"]);
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

test("numbers outside an allowed set get the nearest allowed ones", () => {
  const memory: Rule = { type: "integer", enum: ["512", "1024", "2048"] };
  assert.deepEqual(values(memory, "1500"), ["1024", "2048"]);
  assert.deepEqual(values(memory, "4096"), ["2048"]);
  assert.deepEqual(values(memory, "100"), ["512"]);
  assert.deepEqual(values({ enum: ["STANDARD", "EXPRESS"] }, "100"), []);
});

test("numbers are parsed and clamped", () => {
  assert.deepEqual(values({ type: "integer", min: 1, max: 1000 }, "5000"), ["1000"]);
  assert.deepEqual(values({ type: "integer", min: 1, max: 1000 }, "30s"), ["30"]);
  assert.deepEqual(values({ type: "integer" }, "1,200"), ["1200"]);
});

test("taken names can ignore case", () => {
  assert.equal(check("Alice", { taken: ["alice"] }), null);
  assert.equal(check("Alice", { taken: ["alice"], takenIgnoreCase: true })?.code, "taken");
  assert.deepEqual(values({ taken: ["alice", "ALICE-2"], takenIgnoreCase: true }, "Alice"), ["Alice-3"]);
});

test("taken names get the next free variant", () => {
  assert.deepEqual(values({ taken: ["orders", "orders-2"] }, "orders"), ["orders-3"]);
  assert.deepEqual(values({ taken: ["jobs.fifo"], pattern: "^[a-z-]+\\d*(\\.fifo)?$" }, "jobs.fifo")[0], "jobs-2.fifo".replace("-2", "-2"));
  const email: Rule = { format: "email", taken: ["ops@example.com", "ops+2@example.com"] };
  assert.deepEqual(values(email, "ops@example.com"), ["ops+3@example.com"]);
  assert.deepEqual(values({ format: "email", taken: ["ops+4@example.com"] }, "ops+4@example.com"), ["ops+5@example.com"]);
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

test("over-long JSON is minified", () => {
  const doc = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: "*", Resource: "*" }] }, null, 2);
  assert.deepEqual(values({ format: "json", maxLength: 90 }, doc), [JSON.stringify(JSON.parse(doc))]);
  assert.deepEqual(values({ format: "json", maxLength: 20 }, doc), []);
});

test("phone numbers are repaired to E.164", () => {
  assert.equal(check("+14155550100", { format: "phone" }), null);
  assert.deepEqual(values({ format: "phone" }, "+1 (415) 555-0100"), ["+14155550100"]);
  assert.deepEqual(values({ format: "phone" }, "0044 20 7946 0958"), ["+442079460958"]);
  assert.deepEqual(values({ format: "phone" }, "415-555-0100"), ["+14155550100", "+4155550100"]);
  assert.deepEqual(values({ format: "phone" }, "call me"), []);
});

test("bare names become known ARNs", () => {
  const known = ["arn:aws:sqs:us-east-1:123456789012:orders", "arn:aws:sqs:us-east-1:123456789012:billing"];
  const rule: Rule = { format: "arn", arn: "arn:aws:sqs:us-east-1:123456789012:{}", known };
  assert.deepEqual(values(rule, "orders"), [known[0]]);
  assert.deepEqual(values(rule, "ordrs"), ["arn:aws:sqs:us-east-1:123456789012:ordrs", known[0]]);
});

test("URL schemes follow the page's pattern", () => {
  const http: Rule = { format: "url", pattern: "^http://" };
  const https: Rule = { format: "url", pattern: "^https://" };
  assert.deepEqual(values(http, "example.com/hook"), ["http://example.com/hook"]);
  assert.deepEqual(values(http, "https://example.com/hook"), ["http://example.com/hook"]);
  assert.deepEqual(values(https, "http://example.com/hook"), ["https://example.com/hook"]);
});

test("local URLs get http://, key=value lists are rewritten", () => {
  assert.deepEqual(values({ format: "url" }, "127.0.0.1:11434/v1"), ["http://127.0.0.1:11434/v1"]);
  assert.deepEqual(values({ format: "url" }, "localhost:8080"), ["http://localhost:8080"]);
  assert.deepEqual(values({ format: "url" }, "api.openai.com/v1"), ["https://api.openai.com/v1"]);
  assert.equal(check("x-team=ml\nx-env=dev", { format: "pairs" }), null);
  assert.equal(check("x-team: ml", { format: "pairs" })?.message, '"x-team: ml" is not key=value');
  assert.deepEqual(values({ format: "pairs" }, "x-team: ml\nx-env dev"), ["x-team=ml\nx-env=dev"]);
  assert.deepEqual(values({ format: "pairs" }, '{"x-team": "ml", "n": 2,}'), ["x-team=ml\nn=2"]);
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

test("country codes: capitals, names, withdrawn and alpha-3 codes", () => {
  const rule: Rule = { format: "country" };
  assert.equal(check("DE", rule), null);
  assert.deepEqual(values(rule, "de"), ["DE"]);
  assert.deepEqual(values(rule, "UK"), ["GB"]);
  assert.equal(values(rule, "Germany")[0], "DE");
  assert.equal(values(rule, "USA")[0], "US");
  assert.ok(values(rule, "AUT").includes("AT"));
  assert.match(check("QQ", rule)!.message, /two-letter/);
});

test("CSRs: headers added, surrounding text dropped, keys refused", () => {
  const rule: Rule = { format: "csr" };
  const body = "MIIBVjCB" + "A".repeat(100);
  const tidy = `-----BEGIN CERTIFICATE REQUEST-----\n${body.slice(0, 64)}\n${body.slice(64)}\n-----END CERTIFICATE REQUEST-----`;
  assert.equal(check(tidy, rule), null);
  assert.deepEqual(values(rule, body), [tidy]);
  assert.deepEqual(values(rule, `csr.pem:\n-----BEGIN CERTIFICATE REQUEST-----\n${body}\n-----END CERTIFICATE REQUEST-----\n$ `), [tidy]);
  assert.deepEqual(values(rule, `-----BEGIN CERTIFICATE REQUEST----- ${body} -----END CERTIFICATE REQUEST-----`), [tidy]);
  assert.match(check(`-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`, rule)!.message, /private key/);
  assert.match(check(`-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`, rule)!.message, /certificate, not/);
});

test("policy documents: checked and repaired as policies", () => {
  const rule: Rule = { format: "policy", required: true };
  assert.equal(check('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}', rule), null);
  // A bare statement, lowercase keys and Effect, an action with a dot.
  const issue = check("{effect: 'allow', actions: ['s3.GetObject'], resource: '*'}", rule);
  assert.equal(issue?.code, "format");
  assert.deepEqual(JSON.parse(issue!.repairs[0].value), {
    Version: "2012-10-17",
    Statement: [{ Effect: "Allow", Action: ["s3:GetObject"], Resource: "*" }],
  });
  assert.equal(check('{"Version":"2012-10-17","Statement":{"Effect":"Permit","Action":"*"}}', rule)?.message, "The statement: Effect is Allow or Deny");
  assert.equal(check('{"Statement":[{"Effect":"Allow","Resource":"*"}]}', rule)?.message, "The statement has no Action");
  assert.equal(JSON.parse(repairPolicy('{"Version":"2012-10-18","Statement":[]}')!).Version, "2012-10-17");
});

test("paths start and end with a slash", () => {
  const rule: Rule = { format: "path" };
  assert.equal(check("/team/eng/", rule), null);
  assert.equal(check("team", rule)?.repairs[0].value, "/team/");
  assert.equal(check("/a//b", rule)?.repairs[0].value, "/a/b/");
});

test("email addresses, lists and domains are cleaned up", () => {
  assert.deepEqual(values({ format: "email" }, "mailto:Dev@Example.COM"), ["Dev@example.com"]);
  assert.deepEqual(values({ format: "email" }, "ops@company.con"), ["ops@company.com"]);
  assert.deepEqual(values({ format: "email" }, "Jane Doe <jane@example.com>"), ["jane@example.com"]);
  assert.equal(check("a@example.com, b@example.com", { format: "emails" }), null);
  assert.deepEqual(values({ format: "emails" }, "a@example.com; b@example.con\nA@example.com"), ["a@example.com, b@example.com"]);
  assert.match(check("a@example.com, a@example.com", { format: "emails" })!.message, /twice/);
  assert.deepEqual(values({ format: "domain" }, "https://Mail.Example.com/path"), ["mail.example.com"]);
  assert.deepEqual(values({ format: "domain" }, "example.con"), ["example.com"]);
  assert.equal(check("example.com", { format: "email-or-domain" }), null);
  assert.equal(check("me@example.com", { format: "email-or-domain" }), null);
  assert.deepEqual(values({ format: "email-or-domain" }, "https://example.com/"), ["example.com"]);
  assert.deepEqual(values({ format: "email-or-domain" }, "me@exmaple.com"), ["me@example.com"]);
});

test("a few known values are all offered when none is close", () => {
  const rule: Rule = { pattern: "^(a@example\\.com|b@example\\.com)$", known: ["a@example.com", "b@example.com"] };
  assert.deepEqual(values(rule, "zz@other.org"), ["a@example.com", "b@example.com"]);
});

test("S3 object locations are rewritten to s3:// URLs", () => {
  const rule: Rule = { format: "s3url", maxLength: 300 };
  assert.equal(check("s3://lists/trusted.txt", rule), null);
  assert.equal(check("https://lists.s3.us-east-1.amazonaws.com/trusted.txt", rule), null);
  assert.equal(check("https://s3.amazonaws.com/lists/trusted.txt", rule), null);
  for (const pasted of ["lists/trusted.txt", "arn:aws:s3:::lists/trusted.txt", "S3:/lists/trusted.txt", "https://us-east-1.console.aws.amazon.com/s3/object/lists?region=us-east-1&prefix=trusted.txt"]) {
    assert.deepEqual(values(rule, pasted), ["s3://lists/trusted.txt"], pasted);
  }
  assert.equal(check("s3://lists", rule)?.message, "Like s3://bucket/key");
  // A bucket without a key: the known objects in it are offered.
  assert.deepEqual(values({ ...rule, known: ["s3://lists/trusted.txt", "s3://other/x.csv"] }, "s3://lists"), ["s3://lists/trusted.txt"]);
});
