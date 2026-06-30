// Asymmetric sharing: 1:1 item sharing between users. Each user has an RSA-OAEP
// keypair generated client-side at registration. The public key is uploaded (so
// anyone can encrypt a key to it); the private key is wrapped by the user's
// symmetric User Key and uploaded as `protectedPrivateKey`, so only the unlocked
// user can recover it. The server stores both but can decrypt neither the private
// key nor any shared item.
//
// To share an item the sender encrypts it under a fresh random item key, wraps
// that key to the recipient's public key, and uploads {wrappedKey, data}. The
// recipient unwraps the item key with their private key and decrypts the data.

import { aesGcmDecrypt, aesGcmEncrypt, fromBase64, toBase64, utf8, fromUtf8 } from "./primitives.js";
import { EncType, parseEncString, serializeEncString } from "./encstring.js";

const subtle = globalThis.crypto.subtle;
const RSA_PARAMS = { name: "RSA-OAEP", hash: "SHA-256" } as const;
const SHARE_ITEM_KEY_BYTES = 32;

function userEncKey(userKey: Uint8Array): Uint8Array {
  return userKey.slice(0, 32);
}

export interface UserKeypair {
  publicKey: string; // base64-encoded SPKI
  protectedPrivateKey: string; // EncString: PKCS#8 private key wrapped by the User Key
}

// Generate a sharing keypair and wrap the private key with the User Key.
export async function generateUserKeypair(userKey: Uint8Array): Promise<UserKeypair> {
  const pair = (await subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  )) as CryptoKeyPair;
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
  const wrapped = await aesGcmEncrypt(userEncKey(userKey), pkcs8);
  return {
    publicKey: toBase64(spki),
    protectedPrivateKey: serializeEncString({ type: EncType.AesGcm, nonce: wrapped.nonce, data: wrapped.ciphertext }),
  };
}

async function importPublicKey(spkiB64: string): Promise<CryptoKey> {
  return subtle.importKey("spki", fromBase64(spkiB64), RSA_PARAMS, false, ["encrypt"]);
}

async function importPrivateKey(userKey: Uint8Array, protectedPrivateKey: string): Promise<CryptoKey> {
  const e = parseEncString(protectedPrivateKey);
  const pkcs8 = await aesGcmDecrypt(userEncKey(userKey), e.nonce, e.data);
  return subtle.importKey("pkcs8", pkcs8, RSA_PARAMS, false, ["decrypt"]);
}

export interface ShareEnvelope {
  wrappedKey: string; // base64: the item key encrypted to the recipient's public key
  data: string; // EncString: the item plaintext encrypted under that item key
}

// Build a share of `plaintext` for the holder of `recipientPublicKey`.
export async function createShare(recipientPublicKey: string, plaintext: string): Promise<ShareEnvelope> {
  const itemKey = globalThis.crypto.getRandomValues(new Uint8Array(SHARE_ITEM_KEY_BYTES));
  const enc = await aesGcmEncrypt(itemKey, utf8(plaintext));
  const pub = await importPublicKey(recipientPublicKey);
  const wrapped = new Uint8Array(await subtle.encrypt(RSA_PARAMS, pub, itemKey));
  return {
    wrappedKey: toBase64(wrapped),
    data: serializeEncString({ type: EncType.AesGcm, nonce: enc.nonce, data: enc.ciphertext }),
  };
}

// Open a share addressed to the caller, using their (User-Key-wrapped) private key.
export async function openShare(
  userKey: Uint8Array,
  protectedPrivateKey: string,
  envelope: ShareEnvelope,
): Promise<string> {
  const priv = await importPrivateKey(userKey, protectedPrivateKey);
  const itemKey = new Uint8Array(await subtle.decrypt(RSA_PARAMS, priv, fromBase64(envelope.wrappedKey)));
  const e = parseEncString(envelope.data);
  return fromUtf8(await aesGcmDecrypt(itemKey, e.nonce, e.data));
}
