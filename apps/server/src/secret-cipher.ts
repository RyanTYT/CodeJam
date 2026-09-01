import { createCipheriv, createDecipheriv, randomBytes, createHash } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // GCM recommended nonce length
const VERSION = "v1";

/**
 * Encryption-at-rest for the secrets vault. AES-256-GCM gives confidentiality
 * + auth-tag integrity (tamper → decrypt throws). The key is derived from
 * REAL_UPSTREAM_SECRET so no new secret needs managing.
 */

/** Derive a 32-byte AES-256 key from opaque material (REAL_UPSTREAM_SECRET). */
export function deriveKey(material: string): Buffer {
  return createHash("sha256").update(material).digest();
}

/** Encrypt → "v1:iv(base64):tag(base64):ct(base64)". A fresh IV per call. */
export function encrypt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(":");
}

/** Decrypt. Throws if the ciphertext is malformed or the auth tag fails. */
export function decrypt(packed: string, key: Buffer): string {
  const parts = packed.split(":");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("Invalid ciphertext (expected v1:iv:tag:ct)");
  }
  const iv = Buffer.from(parts[1] ?? "", "base64");
  const tag = Buffer.from(parts[2] ?? "", "base64");
  const ct = Buffer.from(parts[3] ?? "", "base64");
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}
