// Field rules for the EC2 forms: the model's constraints (thin for EC2) plus
// what the EC2 docs state for each name. The repairs themselves live in
// @mws-dashboard/ui/validation.
import type { Rule } from "@mws-dashboard/ui";
import {
  AttachVolume,
  AuthorizeSecurityGroupIngress,
  CopyImage,
  CreateImage,
  CreateKeyPair,
  CreateLaunchTemplate,
  CreateLaunchTemplateVersion,
  CreateSecurityGroup,
  CreateTags,
  CreateVolume,
  ModifyInstanceMetadataOptions,
  RunInstances,
} from "@mws-dashboard/ui/model/ec2";

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

/** An IPv6 source or destination. */
export const IPV6_CIDR: Rule = { pattern: "^[0-9a-fA-F:]*:[0-9a-fA-F:]*/(\\d|[1-9]\\d|1[01]\\d|12[0-8])$", hint: "Like 2001:db8::/32 or ::/0" };

/** "Up to 255 characters: a-z, A-Z, 0-9, spaces and ._-:/()#,@[]+=&;{}!$*". */
export const RULE_DESCRIPTION: Rule = { maxLength: 255, pattern: `^[${GROUP_CHARS}]*$`, hint: GROUP_HINT };

/** Tag keys: up to 128 characters, not starting with aws:. */
export const TAG_KEY: Rule = { ...CreateTags.Tags?.item?.fields?.Key, maxLength: 128, reserved: ["aws:"] };

/** `key=value` lines. */
export const TAG_LINES: Rule = { format: "tags" };

// EBS: the size limits per volume type (GiB), from the EBS volume types page.
export const VOLUME_TYPES = ["gp3", "gp2", "io2", "io1", "st1", "sc1", "standard"] as const;
export const SIZE_LIMITS: Record<string, [number, number]> = { gp3: [1, 16384], gp2: [1, 16384], io1: [4, 16384], io2: [4, 65536], st1: [125, 16384], sc1: [125, 16384], standard: [1, 1024] };

export const VOLUME_SIZE: Rule = { ...CreateVolume.Size, min: 1, max: 65536, hint: "GiB" };
export const VOLUME_TYPE: Rule = CreateVolume.VolumeType;
/** gp3 3,000-80,000; io1 100-64,000; io2 100-256,000. */
export const IOPS: Rule = { ...CreateVolume.Iops, min: 100, max: 256000 };
/** gp3 only: 125-2,000 MiB/s. */
export const THROUGHPUT: Rule = { ...CreateVolume.Throughput, min: 125, max: 2000 };

/** The device names EC2 recommends for EBS data volumes on Linux. */
export const DEVICE: Rule = {
  ...AttachVolume.Device,
  pattern: "^(/dev/(sd[b-z]|xvd[b-z]|sd[b-z][1-9]|nvme[0-9]+n1)|xvd[b-z])$",
  hint: "Like /dev/sdf",
  known: ["/dev/sdf", "/dev/sdg", "/dev/sdh", "/dev/sdi", "/dev/sdj", "/dev/sdk", "/dev/sdl", "/dev/sdm", "/dev/sdn", "/dev/sdo", "/dev/sdp"],
};

export const SNAPSHOT_DESCRIPTION: Rule = { maxLength: 255 };

// AMI names: "3-128 alphanumeric characters, parentheses (()), square
// brackets ([]), spaces ( ), periods (.), slashes (/), dashes (-), single
// quotes ('), at-signs (@), or underscores(_)".
export const IMAGE_NAME: Rule = {
  ...CreateImage.Name,
  pattern: "^[A-Za-z0-9()\\[\\] ./\\-'@_]+$",
  hint: "Letters, digits, spaces and ()[]./-'@_",
  generate: "name",
};
export const IMAGE_DESCRIPTION: Rule = CreateImage.Description;
export const COPY_NAME: Rule = { ...CopyImage.Name, pattern: IMAGE_NAME.pattern, hint: IMAGE_NAME.hint };

/** Launch template names: 3-128 of a-z, A-Z, 0-9, ()./-_ . */
export const TEMPLATE_NAME: Rule = {
  ...CreateLaunchTemplate.LaunchTemplateName,
  ...CreateLaunchTemplateVersion.LaunchTemplateName,
  required: true,
  generate: "name",
};
export const VERSION_DESCRIPTION: Rule = CreateLaunchTemplate.VersionDescription;

/** Optional in a launch template: everything may be left to the launch. */
export const TEMPLATE_IMAGE: Rule = { ...IMAGE, required: false };

export const HOP_LIMIT: Rule = { ...ModifyInstanceMetadataOptions.HttpPutResponseHopLimit, min: 1, max: 64 };

/** OpenSSH, PEM or SSH2 public keys (RSA or ED25519). */
export const PUBLIC_KEY: Rule = {
  required: true,
  pattern: "^(ssh-(rsa|ed25519) [A-Za-z0-9+/=]+( .*)?|-----BEGIN [A-Z ]*PUBLIC KEY-----[\\s\\S]+-----END [A-Z ]*PUBLIC KEY-----|---- BEGIN SSH2 PUBLIC KEY ----[\\s\\S]+)\\s*$",
  hint: "An OpenSSH public key (ssh-ed25519 or ssh-rsa)",
};

/** AWS account IDs to share an image or snapshot with. */
export const ACCOUNT_ID: Rule = { pattern: "^\\d{12}$", hint: "A 12-digit account ID" };

export const ROOT_SIZE: Rule = { ...VOLUME_SIZE, required: false };
