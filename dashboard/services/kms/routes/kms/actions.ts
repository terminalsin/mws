"use server";

import { createECDH, createHash, createPublicKey, publicEncrypt, randomBytes, constants as cryptoConstants, timingSafeEqual } from "node:crypto";

import {
  CancelKeyDeletionCommand,
  CreateAliasCommand,
  CreateGrantCommand,
  CreateKeyCommand,
  DecapsulateCommand,
  DecryptCommand,
  DeleteAliasCommand,
  DeleteImportedKeyMaterialCommand,
  DeriveSharedSecretCommand,
  DisableKeyCommand,
  DisableKeyRotationCommand,
  EnableKeyCommand,
  EnableKeyRotationCommand,
  EncapsulateCommand,
  EncryptCommand,
  GenerateMacCommand,
  GetParametersForImportCommand,
  GetPublicKeyCommand,
  ImportKeyMaterialCommand,
  PutKeyPolicyCommand,
  ReplicateKeyCommand,
  RetireGrantCommand,
  RevokeGrantCommand,
  RotateKeyOnDemandCommand,
  ScheduleKeyDeletionCommand,
  SignCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateAliasCommand,
  UpdateKeyDescriptionCommand,
  UpdatePrimaryRegionCommand,
  VerifyCommand,
  VerifyMacCommand,
  type EncapsulationAlgorithmSpec,
  type EncryptionAlgorithmSpec,
  type GrantOperation,
  type KeySpec,
  type KeyUsageType,
  type MacAlgorithmSpec,
  type OriginType,
  type SigningAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { kms } from "../../lib/clients";
import { SPECS_FOR, defaultUsage, listAliases } from "../../lib/kms";

const page = (_id: string) => "/kms/key";

const aliasName = (alias: string) => (alias.startsWith("alias/") ? alias : `alias/${alias}`);

/** Where KMS's errors land on the forms below. */
const ALIAS_FIELDS = { AliasName: "alias", InvalidAliasNameException: "alias", AlreadyExistsException: "alias" };

/** `key=value` lines as pairs; a line without `=` is a field error. */
function pairs(form: FormData, name: string): [string, string][] {
  return text(form, name)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [k, ...rest] = l.split("=");
      if (!rest.length || !k.trim()) throw new FieldError(name, `Line ${i + 1}: key=value`, "format");
      return [k.trim(), rest.join("=").trim()];
    });
}

export async function createKey(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const alias = text(form, "alias");
    // Checked first, so a taken alias does not leave a new key behind.
    if (alias && (await listAliases()).some((a) => a.AliasName === aliasName(alias))) throw new FieldError("alias", "Already exists", "taken");
    const spec = (text(form, "spec") || "SYMMETRIC_DEFAULT") as KeySpec;
    const usage = (text(form, "usage") || defaultUsage(spec)) as KeyUsageType;
    const allowed = SPECS_FOR[usage] ?? [];
    if (!allowed.includes(spec)) throw new FieldError("spec", `${usage} keys take ${allowed.join(", ")}`, "server", { known: allowed });
    const origin = (text(form, "origin") || "AWS_KMS") as OriginType;
    if (origin === "EXTERNAL" && spec !== "SYMMETRIC_DEFAULT" && !spec.startsWith("HMAC") && !spec.startsWith("RSA") && !spec.startsWith("ECC") && spec !== "SM2")
      throw new FieldError("origin", `Key material can't be imported for ${spec}`);
    const Tags = pairs(form, "tags").map(([TagKey, TagValue]) => ({ TagKey, TagValue }));
    const out = await client.send(
      new CreateKeyCommand({
        KeySpec: spec,
        KeyUsage: usage,
        Origin: origin,
        Description: text(form, "description") || undefined,
        MultiRegion: text(form, "multiRegion") === "on",
        Policy: text(form, "policy") || undefined,
        Tags: Tags.length ? Tags : undefined,
      }),
    );
    const id = out.KeyMetadata!.KeyId!;
    if (alias) {
      try {
        await client.send(new CreateAliasCommand({ AliasName: aliasName(alias), TargetKeyId: id }));
      } catch (e) {
        // Leave no unnamed key behind for a form that failed.
        await client.send(new ScheduleKeyDeletionCommand({ KeyId: id, PendingWindowInDays: 7 })).catch(() => undefined);
        throw e;
      }
    }
    if (spec === "SYMMETRIC_DEFAULT" && origin === "AWS_KMS" && text(form, "rotation") === "on") {
      const days = Number(text(form, "rotationDays") || 0);
      await client.send(new EnableKeyRotationCommand({ KeyId: id, RotationPeriodInDays: days || undefined }));
    }
    return `Created ${alias || id}`;
  }, {
    revalidate: ["/kms"],
    fields: {
      ...ALIAS_FIELDS,
      Description: "description",
      KeySpec: "spec",
      KeyUsage: "usage",
      Origin: "origin",
      Policy: "policy",
      MalformedPolicyDocumentException: "policy",
      Tags: "tags",
      TagException: "tags",
      RotationPeriodInDays: "rotationDays",
    },
  });
}

export async function setEnabled(keyId: string, enable: boolean) {
  return act(
    async () => {
      const client = await kms();
      if (enable) await client.send(new EnableKeyCommand({ KeyId: keyId }));
      else await client.send(new DisableKeyCommand({ KeyId: keyId }));
      return enable ? "Enabled" : "Disabled";
    },
    "/kms",
    page(keyId),
  );
}

export async function setRotation(keyId: string, enable: boolean) {
  return act(async () => {
    const client = await kms();
    if (enable) await client.send(new EnableKeyRotationCommand({ KeyId: keyId }));
    else await client.send(new DisableKeyRotationCommand({ KeyId: keyId }));
    return enable ? "Rotation on" : "Rotation off";
  }, page(keyId));
}

/** Turn rotation on with a period (EnableKeyRotation also changes the period of a key that rotates). */
export async function saveRotationPeriod(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const days = Number(required(form, "days", "Rotation period"));
    await (await kms()).send(new EnableKeyRotationCommand({ KeyId: keyId, RotationPeriodInDays: days }));
    return `Rotates every ${days} days`;
  }, { revalidate: [page(keyId)], fields: { RotationPeriodInDays: "days", ValidationException: "days" } });
}

export async function rotateNow(keyId: string) {
  return act(async () => {
    await (await kms()).send(new RotateKeyOnDemandCommand({ KeyId: keyId }));
    return "Rotation started";
  }, page(keyId));
}

export async function scheduleDeletion(keyId: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const days = Number(text(form, "days") || 30);
      const out = await (await kms()).send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: days }));
      return `Deletes ${out.DeletionDate?.toISOString().slice(0, 10)}`;
    },
    { revalidate: ["/kms", page(keyId)], fields: { PendingWindowInDays: "days", ValidationException: "days" } },
  );
}

export async function cancelDeletion(keyId: string) {
  return act(
    async () => {
      await (await kms()).send(new CancelKeyDeletionCommand({ KeyId: keyId }));
      return "Deletion cancelled; the key is disabled";
    },
    "/kms",
    page(keyId),
  );
}

export async function saveDescription(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await kms()).send(new UpdateKeyDescriptionCommand({ KeyId: keyId, Description: text(form, "description") }));
    return "Description saved";
  }, { revalidate: ["/kms", page(keyId)], fields: { Description: "description" } });
}

export async function addAlias(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const alias = required(form, "alias", "Alias");
    await (await kms()).send(new CreateAliasCommand({ AliasName: aliasName(alias), TargetKeyId: keyId }));
    return `Added ${aliasName(alias)}`;
  }, { revalidate: [page(keyId)], fields: ALIAS_FIELDS });
}

/** Point an alias of this key at another key. */
export async function moveAlias(keyId: string, alias: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = required(form, "target", "Key");
    await (await kms()).send(new UpdateAliasCommand({ AliasName: alias, TargetKeyId: target }));
    return `${alias} now points at ${target}`;
  }, { revalidate: ["/kms", page(keyId)], fields: { TargetKeyId: "target", NotFoundException: "target", ValidationException: "target" } });
}

export async function deleteAlias(keyId: string, alias: string) {
  return act(async () => {
    await (await kms()).send(new DeleteAliasCommand({ AliasName: alias }));
    return `Removed ${alias}`;
  }, page(keyId));
}

export async function saveKeyPolicy(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Policy = required(form, "policy", "Policy");
    try {
      JSON.parse(Policy);
    } catch {
      throw new FieldError("policy", "Invalid JSON", "format");
    }
    await (await kms()).send(new PutKeyPolicyCommand({ KeyId: keyId, PolicyName: "default", Policy }));
    return "Key policy saved";
  }, { revalidate: [page(keyId)], fields: { Policy: "policy", MalformedPolicyDocumentException: "policy" } });
}

/** Save the tag lines as the key's whole tag set: new and changed keys are
 * tagged, keys no longer listed are untagged. */
export async function saveKeyTags(keyId: string, before: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const Tags = pairs(form, "tags").map(([TagKey, TagValue]) => ({ TagKey, TagValue }));
    const gone = before.filter((k) => !Tags.some((t) => t.TagKey === k));
    if (gone.length) await client.send(new UntagResourceCommand({ KeyId: keyId, TagKeys: gone }));
    if (Tags.length) await client.send(new TagResourceCommand({ KeyId: keyId, Tags }));
    return "Tags saved";
  }, { revalidate: [page(keyId)], fields: { Tags: "tags", TagException: "tags", TagKeys: "tags" } });
}

export async function createGrant(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Operations = form.getAll("operations").map(String) as GrantOperation[];
    if (!Operations.length) throw new FieldError("operations", "Choose at least one operation", "required");
    const subset = pairs(form, "contextSubset");
    const equals = pairs(form, "contextEquals");
    if (subset.length && equals.length) throw new FieldError("contextEquals", "Use either an exact context or a subset, not both");
    const out = await (await kms()).send(
      new CreateGrantCommand({
        KeyId: keyId,
        GranteePrincipal: required(form, "grantee", "Grantee principal"),
        RetiringPrincipal: text(form, "retiring") || undefined,
        Name: text(form, "name") || undefined,
        Operations,
        Constraints:
          subset.length || equals.length
            ? { ...(subset.length ? { EncryptionContextSubset: Object.fromEntries(subset) } : {}), ...(equals.length ? { EncryptionContextEquals: Object.fromEntries(equals) } : {}) }
            : undefined,
      }),
    );
    return { ok: true, message: `Created grant ${out.GrantId}`, detail: `Grant token (for eventual consistency):\n${out.GrantToken}` };
  }, {
    revalidate: [page(keyId)],
    fields: { GranteePrincipal: "grantee", RetiringPrincipal: "retiring", Name: "name", Operations: "operations", InvalidArnException: "grantee", MalformedPolicyDocumentException: "grantee" },
  });
}

export async function revokeGrant(keyId: string, grantId: string) {
  return act(async () => {
    await (await kms()).send(new RevokeGrantCommand({ KeyId: keyId, GrantId: grantId }));
    return "Grant revoked";
  }, page(keyId));
}

export async function retireGrant(keyId: string, grantId: string) {
  return act(async () => {
    await (await kms()).send(new RetireGrantCommand({ KeyId: keyId, GrantId: grantId }));
    return "Grant retired";
  }, page(keyId));
}

/** Import key material: the person's own (base64), or 256 random bits for a
 * symmetric key, wrapped with the public key from GetParametersForImport. */
export async function importMaterial(keyId: string, spec: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const given = text(form, "material");
    let material: Buffer;
    if (given) {
      material = Buffer.from(given.replace(/\s+/g, ""), "base64");
      if (!material.length) throw new FieldError("material", "Not base64", "format");
    } else if (spec === "SYMMETRIC_DEFAULT") material = randomBytes(32);
    else if (spec.startsWith("HMAC_")) material = randomBytes(Number(spec.slice(5)) / 8);
    else throw new FieldError("material", "Paste the private key (DER, base64) for an asymmetric key", "required");
    const params = await client.send(new GetParametersForImportCommand({ KeyId: keyId, WrappingAlgorithm: "RSAES_OAEP_SHA_256", WrappingKeySpec: "RSA_4096" }));
    const wrapping = createPublicKey({ key: Buffer.from(params.PublicKey!), format: "der", type: "spki" });
    const EncryptedKeyMaterial = publicEncrypt({ key: wrapping, padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, material);
    const expires = text(form, "validTo");
    await client.send(
      new ImportKeyMaterialCommand({
        KeyId: keyId,
        ImportToken: params.ImportToken,
        EncryptedKeyMaterial,
        ExpirationModel: expires ? "KEY_MATERIAL_EXPIRES" : "KEY_MATERIAL_DOES_NOT_EXPIRE",
        ValidTo: expires ? new Date(expires) : undefined,
      }),
    );
    return given ? "Key material imported" : "Generated key material imported";
  }, { revalidate: ["/kms", page(keyId)], fields: { ValidTo: "validTo", IncorrectKeyMaterialException: "material", InvalidCiphertextException: "material", ExpiredImportTokenException: "material" } });
}

export async function deleteMaterial(keyId: string) {
  return act(async () => {
    await (await kms()).send(new DeleteImportedKeyMaterialCommand({ KeyId: keyId }));
    return "Key material deleted; the key waits for an import";
  }, "/kms", page(keyId));
}

/** Replicate a multi-Region primary key into another Region. */
export async function replicate(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ReplicaRegion = required(form, "region", "Region");
    const out = await (await kms()).send(new ReplicateKeyCommand({ KeyId: keyId, ReplicaRegion, Description: text(form, "description") || undefined }));
    return `Replica ${out.ReplicaKeyMetadata?.Arn} created`;
  }, { revalidate: [page(keyId)], fields: { ReplicaRegion: "region", AlreadyExistsException: "region", UnsupportedOperationException: "region" } });
}

/** Make a replica (in `region`) the primary key. */
export async function makePrimary(keyArn: string, region: string) {
  return act(async () => {
    await (await kms()).send(new UpdatePrimaryRegionCommand({ KeyId: keyArn, PrimaryRegion: region }));
    return `Primary moving to ${region}`;
  }, page(keyArn));
}

const CURVES: Record<string, string> = { ECC_NIST_P256: "prime256v1", ECC_NIST_P384: "secp384r1", ECC_NIST_P521: "secp521r1" };

/** A peer public key as DER: PEM, base64 DER, or nothing (an ephemeral key
 * the console makes, so the result can be checked against its own ECDH). */
function peerKey(input: string) {
  if (!input) return undefined;
  const body = input.includes("BEGIN") ? input.replace(/-----[^-]+-----/g, "") : input;
  const der = Buffer.from(body.replace(/\s+/g, ""), "base64");
  try {
    createPublicKey({ key: der, format: "der", type: "spki" });
  } catch {
    throw new FieldError("plaintext", "Not a public key (SubjectPublicKeyInfo, PEM or base64 DER)", "format");
  }
  return der;
}

/** Use the key on a string by what it does: encrypt and decrypt, sign and
 * verify, MAC and verify, derive a shared secret, or encapsulate and
 * decapsulate. Each runs both halves so the result proves the key works. */
export async function tryKey(keyId: string, usage: string, spec: string, algorithm: string | undefined, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const b64 = (b: Uint8Array | undefined) => Buffer.from(b ?? []).toString("base64");
    if (usage === "KEY_AGREEMENT") {
      const given = peerKey(text(form, "plaintext"));
      const curve = CURVES[spec];
      if (given) {
        const out = await client.send(new DeriveSharedSecretCommand({ KeyId: keyId, KeyAgreementAlgorithm: "ECDH", PublicKey: given }));
        return { ok: true, message: "Shared secret derived", detail: b64(out.SharedSecret) };
      }
      if (!curve) throw new FieldError("plaintext", "Paste the peer's public key", "required");
      // An ephemeral peer: KMS's secret must equal the peer's own ECDH with the key's public half.
      const peer = createECDH(curve);
      peer.generateKeys();
      const spki = createPublicKey({ key: { kty: "EC", crv: { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" }[curve]!, ...jwkXY(peer.getPublicKey(), curve) }, format: "jwk" }).export({ type: "spki", format: "der" });
      const [out, pub] = await Promise.all([
        client.send(new DeriveSharedSecretCommand({ KeyId: keyId, KeyAgreementAlgorithm: "ECDH", PublicKey: spki })),
        client.send(new GetPublicKeyCommand({ KeyId: keyId })),
      ]);
      const ours = createPublicKey({ key: Buffer.from(pub.PublicKey!), format: "der", type: "spki" }).export({ format: "jwk" });
      const point = Buffer.concat([Buffer.from([4]), Buffer.from(ours.x!, "base64url"), Buffer.from(ours.y!, "base64url")]);
      const local = peer.computeSecret(point);
      const match = out.SharedSecret && Buffer.from(out.SharedSecret).length === local.length && timingSafeEqual(Buffer.from(out.SharedSecret), local);
      if (!match) throw new Error("KMS's shared secret differs from the peer's ECDH result");
      return { ok: true, message: "Shared secret matches the peer's", detail: b64(out.SharedSecret) };
    }
    if (usage === "ENCAPSULATE_DECAPSULATE") {
      const EncapsulationAlgorithm = (algorithm ?? "ML_KEM") as EncapsulationAlgorithmSpec;
      const enc = await client.send(new EncapsulateCommand({ KeyId: keyId, EncapsulationAlgorithm }));
      const dec = await client.send(new DecapsulateCommand({ KeyId: keyId, EncapsulationAlgorithm, SharedSecretCiphertextBlob: enc.SharedSecretCiphertextBlob }));
      const same = Buffer.from(enc.SharedSecret ?? []).equals(Buffer.from(dec.SharedSecret ?? []));
      if (!same) throw new Error("Decapsulated secret differs from the encapsulated one");
      return {
        ok: true,
        message: "Encapsulated and decapsulated the same secret",
        detail: `secret ${createHash("sha256").update(Buffer.from(dec.SharedSecret!)).digest("hex").slice(0, 16)}… (sha-256)\nciphertext ${b64(enc.SharedSecretCiphertextBlob).slice(0, 64)}…`,
      };
    }
    const input = new TextEncoder().encode(required(form, "plaintext", "Text"));
    if (usage === "SIGN_VERIFY") {
      const SigningAlgorithm = algorithm as SigningAlgorithmSpec;
      const out = await client.send(new SignCommand({ KeyId: keyId, Message: input, MessageType: "RAW", SigningAlgorithm }));
      const check = await client.send(new VerifyCommand({ KeyId: keyId, Message: input, MessageType: "RAW", SigningAlgorithm, Signature: out.Signature }));
      return { ok: true, message: `Signed with ${out.SigningAlgorithm}${check.SignatureValid ? ", signature valid" : ""}`, detail: b64(out.Signature) };
    }
    if (usage === "GENERATE_VERIFY_MAC") {
      const MacAlgorithm = algorithm as MacAlgorithmSpec;
      const out = await client.send(new GenerateMacCommand({ KeyId: keyId, Message: input, MacAlgorithm }));
      const check = await client.send(new VerifyMacCommand({ KeyId: keyId, Message: input, MacAlgorithm, Mac: out.Mac }));
      return { ok: true, message: `${out.MacAlgorithm}${check.MacValid ? ", MAC valid" : ""}`, detail: b64(out.Mac) };
    }
    const EncryptionAlgorithm = algorithm as EncryptionAlgorithmSpec | undefined;
    const encrypted = await client.send(new EncryptCommand({ KeyId: keyId, Plaintext: input, EncryptionAlgorithm }));
    const decrypted = await client.send(new DecryptCommand({ CiphertextBlob: encrypted.CiphertextBlob, KeyId: keyId, EncryptionAlgorithm }));
    return {
      ok: true,
      message: "Round trip ok",
      detail: `${b64(encrypted.CiphertextBlob)}\n\n→ ${new TextDecoder().decode(decrypted.Plaintext)}`,
    };
  }, { fields: { Plaintext: "plaintext", Message: "plaintext", PublicKey: "plaintext", ValidationException: "plaintext" } });
}

/** An uncompressed EC point as JWK coordinates. */
function jwkXY(point: Buffer, curve: string) {
  const size = { prime256v1: 32, secp384r1: 48, secp521r1: 66 }[curve]!;
  return { x: point.subarray(1, 1 + size).toString("base64url"), y: point.subarray(1 + size).toString("base64url") };
}
