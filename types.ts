
export interface User {
  id: string;
  username: string;
  displayName: string;
  avatar: string;
  passwordHash: string;
  twoFactorSecret: string;
  isOnline: boolean;
  createdAt: number;
}

export interface Message {
  id: string;
  senderId: string;
  receiverId: string;
  encryptedContent: string;
  iv: string; // Initialization Vector for AES
  timestamp: number;
  status: 'sent' | 'delivered' | 'read';
}

export interface ChatSession {
  participantId: string;
  lastMessage?: Message;
  unreadCount: number;
}

export type AuthStep = 'login' | 'register' | '2fa' | 'authenticated';

export interface CryptoKeyBundle {
  key: CryptoKey;
  raw: Uint8Array;
}
