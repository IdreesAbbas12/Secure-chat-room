
import { CryptoKeyBundle } from './types';

/**
 * Hash a string using SHA-256
 */
export async function sha256(message: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a deterministic AES-256 key from a shared secret (e.g., participants' IDs)
 * In a real-world app, use Diffie-Hellman, but for this demo we'll use a derived key.
 */
export async function deriveKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('cipherchat-salt-constant'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt content with AES-256-GCM
 */
export async function encryptMessage(text: string, key: CryptoKey): Promise<{ encrypted: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  return {
    encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

/**
 * Decrypt content with AES-256-GCM
 */
export async function decryptMessage(encryptedBase64: string, ivBase64: string, key: CryptoKey): Promise<string> {
  try {
    const encrypted = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
    const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('Decryption failed', e);
    return '[Decryption Error: Key Mismatch]';
  }
}

/**
 * Create a simple 2FA code
 */
export function generate2FACode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
