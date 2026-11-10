import assert from "node:assert/strict";
import { test } from "node:test";

import { check, parseServerIssues, type Rule } from "./validation.ts";

// Repairs added for the EC2 forms: port ranges, names standing for IDs, and
// EC2's "Invalid value" messages.

const values = (r: Rule, v: string) => check(v, r)?.repairs.map((x) => x.value) ?? [];

test("port ranges are reordered, joined and named", () => {
  const rule: Rule = { required: true, format: "ports" };
  assert.equal(check("443", rule), null);
  assert.equal(check("8000-8080", rule), null);
  assert.deepEqual(values(rule, "8080-8000"), ["8000-8080"]);
  assert.deepEqual(values(rule, "8000 to 8080"), ["8000-8080"]);
  assert.deepEqual(values(rule, "22/tcp"), ["22"]);
  assert.deepEqual(values(rule, "SSH"), ["22"]);
  assert.deepEqual(values(rule, "all"), ["0-65535"]);
  assert.deepEqual(values(rule, "70000"), ["65535"]);
});

test("names stand for their values", () => {
  const image: Rule = { pattern: "^ami-[0-9a-f]+$", aliases: { "ubuntu-24.04-amd64": "ami-0abc", "alpine-3.20": "ami-0def" } };
  assert.deepEqual(values(image, "ubuntu 24.04"), ["ami-0abc"]);
  assert.deepEqual(values(image, "alpine-3.20"), ["ami-0def"]);
});

test("EC2 'Invalid value' messages name their member", () => {
  assert.deepEqual(parseServerIssues("Invalid value 'clé' for keyName."), [{ member: "keyName", value: "clé", code: "server", message: "Not accepted" }]);
  const [range] = parseServerIssues("Invalid value 'Invalid TCP/UDP port range 443-80' for portRange");
  assert.equal(range.member, "portRange");
  assert.equal(range.message, "Invalid TCP/UDP port range 443-80");
  const [name] = parseServerIssues("Invalid value 'x' for groupName. Length of group name must be between 1 and 255 characters.");
  assert.equal(name.message, "Length of group name must be between 1 and 255 characters");
});
