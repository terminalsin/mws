// Field rules for the EC2 forms: the model's constraints (thin for EC2) plus
// what the EC2 docs state for each name. The repairs themselves live in
// @mws-dashboard/ui/validation.
import type { Rule } from "@mws-dashboard/ui";
import { AuthorizeSecurityGroupIngress, CreateKeyPair, CreateSecurityGroup, CreateTags, RunInstances } from "@mws-dashboard/ui/model/ec2";

export const IMAGE: Rule = { ...RunInstances.ImageId, required: true, pattern: "^ami-[0-9a-f]{8,17}$", hint: "An image ID, like ami-0abcd1234" };

export const INSTANCE_TYPE: Rule = RunInstances.InstanceType;

export const COUNT: Rule = { ...RunInstances.MaxCount, min: 1 };

/** EC2 tag values: up to 256 characters. */
export const TAG_VALUE: Rule = { ...CreateTags.Tags?.item?.fields?.Value, maxLength: 256 };

/** "Up to 255 ASCII characters." */
export const KEY_NAME: Rule = { ...CreateKeyPair.KeyName, maxLength: 255, pattern: "^[ -~]+$", hint: "ASCII characters", generate: "name" };

// "a-z, A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*", and a group name
// cannot start with sg-.
const GROUP_CHARS = "A-Za-z0-9 ._\\-:/()#,@\\[\\]+=&;{}!$*";
const GROUP_HINT = "Letters, digits, spaces and ._-:/()#,@[]+=&;{}!$*";

export const GROUP_NAME: Rule = {
  ...CreateSecurityGroup.GroupName,
  maxLength: 255,
  pattern: `^[${GROUP_CHARS}]+$`,
  reserved: ["sg-"],
  hint: GROUP_HINT,
  generate: "name",
};

/** Optional in the form: the name stands in when it is empty. */
export const GROUP_DESCRIPTION: Rule = { ...CreateSecurityGroup.Description, required: false, maxLength: 255, pattern: `^[${GROUP_CHARS}]*$`, hint: GROUP_HINT };

export const PORTS: Rule = { format: "ports" };

export const SOURCE_CIDR: Rule = { ...AuthorizeSecurityGroupIngress.CidrIp, format: "cidr" };
