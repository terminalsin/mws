// Envelope encryption: KMS hands out a fresh data key per record, the record
// is encrypted locally with AES-256-GCM, and only the KMS-encrypted copy of
// the data key is stored. The encryption context binds the ciphertext to the
// record it belongs to: decrypting with a different context fails.
import { DecryptCommand, GenerateDataKeyCommand } from "@aws-sdk/client-kms";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { kms } from "./clients.js";

export interface SealedRecord {
  encryptedKey: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export async function seal(keyId: string, plaintext: string, context: Record<string, string>): Promise<SealedRecord> {
  const { Plaintext, CiphertextBlob } = await kms.send(
    new GenerateDataKeyCommand({ KeyId: keyId, KeySpec: "AES_256", EncryptionContext: context }),
  );
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Plaintext!, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  Plaintext!.fill(0);
  return {
    encryptedKey: Buffer.from(CiphertextBlob!).toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

export async function open(record: SealedRecord, context: Record<string, string>): Promise<string> {
  // No KeyId needed: the encrypted data key names the KMS key it came from.
  const { Plaintext } = await kms.send(
    new DecryptCommand({ CiphertextBlob: Buffer.from(record.encryptedKey, "base64"), EncryptionContext: context }),
  );
  const decipher = createDecipheriv("aes-256-gcm", Plaintext!, Buffer.from(record.iv, "base64"));
  decipher.setAuthTag(Buffer.from(record.authTag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "base64")), decipher.final()]).toString("utf8");
}
