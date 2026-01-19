
import { User, Message } from './types';

const USERS_KEY = 'cipherchat_users';
const MESSAGES_KEY = 'cipherchat_messages';
const CURRENT_USER_KEY = 'cipherchat_session';

export const storageService = {
  getUsers: (): User[] => {
    const data = localStorage.getItem(USERS_KEY);
    return data ? JSON.parse(data) : [];
  },

  saveUser: (user: User) => {
    const users = storageService.getUsers();
    const existing = users.findIndex(u => u.username === user.username);
    if (existing > -1) {
      users[existing] = user;
    } else {
      users.push(user);
    }
    localStorage.setItem(USERS_KEY, JSON.stringify(users));
  },

  getMessages: (): Message[] => {
    const data = localStorage.getItem(MESSAGES_KEY);
    return data ? JSON.parse(data) : [];
  },

  saveMessage: (msg: Message) => {
    const msgs = storageService.getMessages();
    msgs.push(msg);
    localStorage.setItem(MESSAGES_KEY, JSON.stringify(msgs));
  },

  setCurrentUser: (user: User | null) => {
    if (user) {
      localStorage.setItem(CURRENT_USER_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(CURRENT_USER_KEY);
    }
  },

  getCurrentUser: (): User | null => {
    const data = localStorage.getItem(CURRENT_USER_KEY);
    return data ? JSON.parse(data) : null;
  },

  clearAll: () => {
    localStorage.clear();
  }
};
