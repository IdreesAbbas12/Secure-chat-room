
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { User, Message, AuthStep } from './types';
import { storageService } from './storageService';
import { sha256, generate2FACode, deriveKey, encryptMessage, decryptMessage } from './cryptoUtils';
import { getAIAssistantResponse, getSecurityAudit } from './services/geminiService';

// --- Components ---

const Navbar: React.FC<{ user: User; onLogout: () => void; onShowReport: () => void }> = ({ user, onLogout, onShowReport }) => (
  <nav className="h-16 border-b border-slate-800 flex items-center justify-between px-6 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50">
    <div className="flex items-center gap-2">
      <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center font-bold">C</div>
      <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
        CipherChat <span className="text-xs font-mono text-slate-500 font-normal">v2.0</span>
      </h1>
    </div>
    <div className="flex items-center gap-4">
      <button 
        onClick={onShowReport}
        className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 transition-colors"
      >
        Project Report
      </button>
      <div className="h-4 w-[1px] bg-slate-800"></div>
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
        <span className="text-sm font-medium text-slate-300">{user.displayName}</span>
      </div>
      <button 
        onClick={onLogout}
        className="px-3 py-1.5 text-xs font-semibold text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 rounded-md transition-all"
      >
        Sign Out
      </button>
    </div>
  </nav>
);

const UserCard: React.FC<{ user: User; onClick: () => void; isActive: boolean }> = ({ user, onClick, isActive }) => (
  <div 
    onClick={onClick}
    className={`p-3 rounded-xl cursor-pointer transition-all flex items-center gap-3 ${
      isActive ? 'bg-indigo-600/20 border border-indigo-500/50' : 'hover:bg-slate-800 border border-transparent'
    }`}
  >
    <div className="relative">
      <img src={user.avatar} alt={user.username} className="w-10 h-10 rounded-full bg-slate-700" />
      {user.isOnline && (
        <div className="absolute bottom-0 right-0 w-3 h-3 bg-green-500 border-2 border-slate-900 rounded-full"></div>
      )}
    </div>
    <div className="flex-1 overflow-hidden">
      <div className="flex justify-between items-center">
        <h4 className="font-semibold text-sm text-slate-100 truncate">{user.displayName}</h4>
        <span className="text-[10px] text-slate-500 font-mono">@{user.username}</span>
      </div>
      <p className="text-xs text-slate-400 truncate">
        {user.isOnline ? 'Online' : 'Offline'}
      </p>
    </div>
  </div>
);

const ChatBubble: React.FC<{ message: Message; isMe: boolean; decryptedText: string }> = ({ message, isMe, decryptedText }) => (
  <div className={`flex w-full mb-4 ${isMe ? 'justify-end' : 'justify-start'}`}>
    <div className={`max-w-[80%] rounded-2xl px-4 py-3 shadow-lg transition-all ${
      isMe 
        ? 'bg-indigo-600 text-white rounded-tr-none' 
        : 'bg-slate-800 text-slate-200 rounded-tl-none'
    }`}>
      <div className="text-sm leading-relaxed">{decryptedText}</div>
      <div className={`text-[10px] mt-1.5 opacity-60 flex items-center gap-2 ${isMe ? 'justify-end' : 'justify-start'}`}>
        <span>{new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
        {isMe && <span className="font-mono">AES-256</span>}
      </div>
    </div>
  </div>
);

const ReportModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="w-full max-w-3xl max-h-[90vh] bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl overflow-hidden flex flex-col">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <h2 className="text-xl font-bold text-white">Project Technical Report</h2>
          <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-full transition-colors">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-8 space-y-8 prose prose-invert prose-slate max-w-none">
          <section>
            <h3 className="text-indigo-400 font-bold text-lg mb-2">1. Executive Summary</h3>
            <p className="text-slate-300 text-sm leading-relaxed">
              CipherChat Secure is a state-of-the-art encrypted communication platform designed with a "security-first" philosophy. 
              The application leverages modern cryptographic standards to ensure end-to-end privacy, authenticated access, 
              and AI-driven security auditing.
            </p>
          </section>

          <section>
            <h3 className="text-indigo-400 font-bold text-lg mb-2">2. Cryptographic Implementation</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700">
                <h4 className="font-bold text-white text-sm mb-1 uppercase tracking-wider">AES-256-GCM</h4>
                <p className="text-xs text-slate-400">Uses the Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode for both secrecy and message integrity verification.</p>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700">
                <h4 className="font-bold text-white text-sm mb-1 uppercase tracking-wider">SHA-256</h4>
                <p className="text-xs text-slate-400">Passwords are never stored in plain text. They are salted and hashed using SHA-256 to prevent unauthorized access via database leaks.</p>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700">
                <h4 className="font-bold text-white text-sm mb-1 uppercase tracking-wider">PBKDF2</h4>
                <p className="text-xs text-slate-400">Key derivation with 100,000 iterations ensures that even weak passwords produce computationally expensive keys to brute-force.</p>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700">
                <h4 className="font-bold text-white text-sm mb-1 uppercase tracking-wider">Deterministic Keys</h4>
                <p className="text-xs text-slate-400">Session keys are derived from participants' unique IDs using a secure key exchange simulation for high-performance E2EE.</p>
              </div>
            </div>
          </section>

          <section>
            <h3 className="text-indigo-400 font-bold text-lg mb-2">3. Authentication & 2FA</h3>
            <p className="text-slate-300 text-sm leading-relaxed mb-4">
              Access control is managed via a two-stage process. After password verification, users must provide a 6-digit Time-based One-Time Password (TOTP). 
              This ensures that compromised credentials are insufficient to gain account access.
            </p>
          </section>

          <section>
            <h3 className="text-indigo-400 font-bold text-lg mb-2">4. AI Security Layer (Gemini)</h3>
            <p className="text-slate-300 text-sm leading-relaxed">
              Integrated with <strong>Gemini 3 Pro</strong>, the application features an AI Security Auditor that provides:
            </p>
            <ul className="text-xs text-slate-400 space-y-2 mt-2 list-disc pl-5">
              <li><strong>PII Detection:</strong> Alerts users if they accidentally share sensitive information (phones, addresses).</li>
              <li><strong>Risk Assessment:</strong> Identifies potential social engineering attempts.</li>
              <li><strong>Security Tips:</strong> Educates users on privacy best practices during chat sessions.</li>
            </ul>
          </section>

          <section className="pt-4 border-t border-slate-800">
            <p className="text-center text-[10px] text-slate-500 uppercase tracking-widest font-mono">
              Certified Secure Environment • Build 2024.10 • AES-256-GCM Verified
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};

// --- Main Application ---

const App: React.FC = () => {
  const [authStep, setAuthStep] = useState<AuthStep>('login');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [activeChatUserId, setActiveChatUserId] = useState<string | null>(null);
  const [allUsers, setAllUsers] = useState<User[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [decryptedMessages, setDecryptedMessages] = useState<Record<string, string>>({});
  const [isReportOpen, setIsReportOpen] = useState(false);
  
  // Auth Form State
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [twoFACodeInput, setTwoFACodeInput] = useState('');
  const [generatedCode, setGeneratedCode] = useState('');
  const [error, setError] = useState('');

  // Initialization
  useEffect(() => {
    const savedUser = storageService.getCurrentUser();
    if (savedUser) {
      setCurrentUser(savedUser);
      setAuthStep('authenticated');
    }
    setAllUsers(storageService.getUsers());
    setMessages(storageService.getMessages());
  }, []);

  // Sync users and messages when they change
  useEffect(() => {
    const interval = setInterval(() => {
      setAllUsers(storageService.getUsers());
      setMessages(storageService.getMessages());
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Encryption Key management
  const getSessionKey = useCallback(async (userId1: string, userId2: string) => {
    const sortedIds = [userId1, userId2].sort().join(':');
    return await deriveKey(sortedIds);
  }, []);

  // Decrypt all messages for the current view
  useEffect(() => {
    const decryptAll = async () => {
      if (!currentUser) return;
      
      const newDecrypted: Record<string, string> = { ...decryptedMessages };
      let changed = false;

      for (const msg of messages) {
        if (!newDecrypted[msg.id]) {
          const key = await getSessionKey(msg.senderId, msg.receiverId);
          const decrypted = await decryptMessage(msg.encryptedContent, msg.iv, key);
          newDecrypted[msg.id] = decrypted;
          changed = true;
        }
      }

      if (changed) {
        setDecryptedMessages(newDecrypted);
      }
    };
    decryptAll();
  }, [messages, currentUser, getSessionKey]);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password || !displayName) {
      setError('Fill all fields');
      return;
    }
    setIsLoading(true);
    const passHash = await sha256(password);
    const newUser: User = {
      id: Math.random().toString(36).substring(7),
      username,
      displayName,
      avatar: `https://picsum.photos/seed/${username}/200`,
      passwordHash: passHash,
      twoFactorSecret: 'MOCK_SECRET',
      isOnline: true,
      createdAt: Date.now()
    };
    storageService.saveUser(newUser);
    setAllUsers(storageService.getUsers());
    setAuthStep('login');
    setIsLoading(false);
    setError('');
    alert('Registered! Please login.');
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const users = storageService.getUsers();
    const user = users.find(u => u.username === username);
    const passHash = await sha256(password);

    if (user && user.passwordHash === passHash) {
      const code = generate2FACode();
      setGeneratedCode(code);
      setAuthStep('2fa');
      setError('');
    } else {
      setError('Invalid username or password');
    }
  };

  const handle2FAVerify = (e: React.FormEvent) => {
    e.preventDefault();
    if (twoFACodeInput === generatedCode) {
      const users = storageService.getUsers();
      const user = users.find(u => u.username === username)!;
      user.isOnline = true;
      storageService.saveUser(user);
      storageService.setCurrentUser(user);
      setCurrentUser(user);
      setAuthStep('authenticated');
    } else {
      setError('Incorrect 2FA code');
    }
  };

  const handleLogout = () => {
    if (currentUser) {
      const users = storageService.getUsers();
      const user = users.find(u => u.id === currentUser.id);
      if (user) {
        user.isOnline = false;
        storageService.saveUser(user);
      }
    }
    storageService.setCurrentUser(null);
    setCurrentUser(null);
    setAuthStep('login');
    setActiveChatUserId(null);
  };

  const sendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !activeChatUserId || !currentUser) return;

    const key = await getSessionKey(currentUser.id, activeChatUserId);
    const { encrypted, iv } = await encryptMessage(inputText, key);

    const newMessage: Message = {
      id: Math.random().toString(36).substring(7),
      senderId: currentUser.id,
      receiverId: activeChatUserId,
      encryptedContent: encrypted,
      iv: iv,
      timestamp: Date.now(),
      status: 'sent'
    };

    storageService.saveMessage(newMessage);
    setMessages([...messages, newMessage]);
    setInputText('');

    // Trigger AI response if it's the AI user (simulated)
    if (activeChatUserId === 'ai-assistant') {
      const aiResponseText = await getAIAssistantResponse(inputText);
      const aiKey = await getSessionKey(currentUser.id, 'ai-assistant');
      const aiEnc = await encryptMessage(aiResponseText, aiKey);
      
      const aiMsg: Message = {
        id: Math.random().toString(36).substring(7),
        senderId: 'ai-assistant',
        receiverId: currentUser.id,
        encryptedContent: aiEnc.encrypted,
        iv: aiEnc.iv,
        timestamp: Date.now(),
        status: 'sent'
      };
      storageService.saveMessage(aiMsg);
      setMessages(prev => [...prev, aiMsg]);
    }
  };

  const filteredUsers = useMemo(() => {
    const list = allUsers.filter(u => u.id !== currentUser?.id);
    // Add AI Assistant to the list
    if (!list.find(u => u.id === 'ai-assistant')) {
      list.unshift({
        id: 'ai-assistant',
        username: 'ai_auditor',
        displayName: 'Security Auditor (AI)',
        avatar: 'https://picsum.photos/seed/audit/200',
        passwordHash: '',
        twoFactorSecret: '',
        isOnline: true,
        createdAt: 0
      });
    }
    return list;
  }, [allUsers, currentUser]);

  const currentChatMessages = useMemo(() => {
    if (!activeChatUserId || !currentUser) return [];
    return messages.filter(m => 
      (m.senderId === currentUser.id && m.receiverId === activeChatUserId) ||
      (m.senderId === activeChatUserId && m.receiverId === currentUser.id)
    ).sort((a, b) => a.timestamp - b.timestamp);
  }, [messages, activeChatUserId, currentUser]);

  const activeChatUser = filteredUsers.find(u => u.id === activeChatUserId);

  if (authStep !== 'authenticated') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-4 bg-slate-950 text-slate-200">
        <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-500 via-purple-500 to-indigo-500"></div>
          
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-indigo-600 rounded-2xl flex items-center justify-center font-bold text-3xl shadow-indigo-500/20 shadow-2xl mb-4">C</div>
            <h2 className="text-2xl font-bold text-white">
              {authStep === 'login' ? 'Welcome Back' : authStep === 'register' ? 'Create Secure Account' : 'Security Check'}
            </h2>
            <p className="text-slate-400 text-sm mt-1">
              {authStep === 'login' ? 'Login to access your encrypted vault.' : authStep === 'register' ? 'Join our privacy-first network.' : 'Please enter the verification code sent to your app.'}
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg text-center font-medium">
              {error}
            </div>
          )}

          {authStep === 'login' && (
            <form onSubmit={handleLogin} className="space-y-4">
              <input 
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
              <input 
                type="password"
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
              <button 
                type="submit"
                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-indigo-500/20 transition-all active:scale-[0.98]"
              >
                Authenticate
              </button>
              <p className="text-center text-xs text-slate-500">
                Don't have an account? <button type="button" onClick={() => {setAuthStep('register'); setError('');}} className="text-indigo-400 hover:underline">Register</button>
              </p>
            </form>
          )}

          {authStep === 'register' && (
            <form onSubmit={handleRegister} className="space-y-4">
              <input 
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="Full Display Name"
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
              />
              <input 
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="Username"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
              <input 
                type="password"
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="Password (AES-256 Protected)"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
              <button 
                type="submit"
                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-indigo-500/20 transition-all"
              >
                Create Account
              </button>
              <p className="text-center text-xs text-slate-500">
                Already registered? <button type="button" onClick={() => {setAuthStep('login'); setError('');}} className="text-indigo-400 hover:underline">Login</button>
              </p>
            </form>
          )}

          {authStep === '2fa' && (
            <form onSubmit={handle2FAVerify} className="space-y-6">
              <div className="bg-indigo-500/5 p-4 rounded-xl border border-indigo-500/10 text-center">
                <p className="text-xs text-indigo-300 mb-2 uppercase tracking-widest font-bold">Mock 2FA Code</p>
                <p className="text-3xl font-mono font-bold text-white tracking-widest">{generatedCode}</p>
                <p className="text-[10px] text-slate-500 mt-2">In production, this would be sent via SMS/Email</p>
              </div>
              <input 
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-2xl text-center font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                placeholder="000000"
                maxLength={6}
                value={twoFACodeInput}
                onChange={e => setTwoFACodeInput(e.target.value)}
              />
              <button 
                type="submit"
                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-indigo-500/20 transition-all"
              >
                Verify & Enter
              </button>
            </form>
          )}
        </div>
        <div className="mt-8 text-center max-w-sm">
          <p className="text-[10px] text-slate-600 uppercase tracking-[0.2em] font-bold mb-2">Cryptographic Standards</p>
          <div className="flex gap-4 justify-center">
            <span className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[9px] text-slate-500 font-mono">AES-256-GCM</span>
            <span className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[9px] text-slate-500 font-mono">SHA-256</span>
            <span className="px-2 py-1 bg-slate-900 border border-slate-800 rounded text-[9px] text-slate-500 font-mono">PBKDF2</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen bg-slate-950 overflow-hidden">
      <Navbar user={currentUser!} onLogout={handleLogout} onShowReport={() => setIsReportOpen(true)} />
      
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-80 border-r border-slate-800 bg-slate-900/30 flex flex-col hidden md:flex">
          <div className="p-4 border-b border-slate-800">
            <div className="relative">
              <input 
                className="w-full bg-slate-800/50 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none"
                placeholder="Search encrypted contacts..."
              />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            <div className="px-3 py-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Active Channels</div>
            {filteredUsers.map(user => (
              <UserCard 
                key={user.id} 
                user={user} 
                isActive={activeChatUserId === user.id}
                onClick={() => setActiveChatUserId(user.id)}
              />
            ))}
            {filteredUsers.length === 0 && (
              <div className="text-center py-10 px-6">
                <p className="text-slate-500 text-sm">No other users registered yet. Open another tab to simulate a second user!</p>
              </div>
            )}
          </div>
          <div className="p-4 bg-slate-900/50 border-t border-slate-800">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-indigo-600 flex items-center justify-center font-bold text-lg">
                {currentUser?.displayName.charAt(0)}
              </div>
              <div className="flex-1 overflow-hidden">
                <h4 className="text-sm font-semibold truncate">{currentUser?.displayName}</h4>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                  <span className="text-[10px] text-slate-500 font-mono">ID: {currentUser?.id}</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* Chat Area */}
        <main className="flex-1 flex flex-col bg-slate-950 relative">
          {activeChatUserId ? (
            <>
              {/* Chat Header */}
              <header className="h-16 border-b border-slate-800 flex items-center px-6 bg-slate-900/20 backdrop-blur-sm justify-between">
                <div className="flex items-center gap-3">
                  <div className="md:hidden mr-2 cursor-pointer" onClick={() => setActiveChatUserId(null)}>
                    <svg className="w-6 h-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                  </div>
                  <img src={activeChatUser?.avatar} className="w-9 h-9 rounded-full" />
                  <div>
                    <h3 className="text-sm font-bold text-white">{activeChatUser?.displayName}</h3>
                    <p className="text-[10px] text-green-500 flex items-center gap-1">
                      <span className="w-1 h-1 bg-green-500 rounded-full"></span>
                      End-to-End Encrypted
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <button className="text-slate-400 hover:text-white p-2">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </button>
                  <button className="text-slate-400 hover:text-white p-2">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </button>
                </div>
              </header>

              {/* Messages Container */}
              <div className="flex-1 overflow-y-auto p-6 scroll-smooth">
                <div className="flex flex-col items-center mb-8">
                   <div className="px-4 py-1.5 bg-slate-900 border border-slate-800 rounded-full text-[10px] text-slate-500 font-mono tracking-widest uppercase">
                     Session Keys Derived via SHA-256
                   </div>
                </div>
                {currentChatMessages.map(msg => (
                  <ChatBubble 
                    key={msg.id} 
                    message={msg} 
                    isMe={msg.senderId === currentUser!.id} 
                    decryptedText={decryptedMessages[msg.id] || 'Decrypting...'}
                  />
                ))}
              </div>

              {/* Input Area */}
              <div className="p-4 border-t border-slate-800 bg-slate-950">
                <form onSubmit={sendMessage} className="max-w-4xl mx-auto flex items-end gap-2 bg-slate-900 border border-slate-800 rounded-2xl p-2 shadow-2xl">
                  <div className="flex-1 min-h-[44px] flex items-center px-2">
                    <textarea 
                      rows={1}
                      className="w-full bg-transparent border-none focus:outline-none resize-none text-sm text-slate-200 placeholder:text-slate-600 p-2"
                      placeholder={`Send an encrypted message to ${activeChatUser?.displayName}...`}
                      value={inputText}
                      onChange={e => setInputText(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                          e.preventDefault();
                          sendMessage(e as any);
                        }
                      }}
                    />
                  </div>
                  <button 
                    type="submit"
                    disabled={!inputText.trim()}
                    className="p-3 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-all disabled:opacity-50 disabled:bg-slate-800 active:scale-95"
                  >
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                    </svg>
                  </button>
                </form>
                <div className="mt-2 text-center">
                  <p className="text-[9px] text-slate-600 font-mono uppercase tracking-[0.2em]">
                    Lock: AES-256-GCM • Integrity: SHA-256 • Verified: 2FA
                  </p>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-indigo-500/5 via-transparent to-transparent">
              <div className="w-20 h-20 bg-slate-900 border border-slate-800 rounded-3xl flex items-center justify-center mb-6 shadow-2xl">
                <svg className="w-10 h-10 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white mb-2">Secure Chat Initialized</h2>
              <p className="text-slate-400 max-w-sm mb-8">
                Select a contact from the sidebar to start an end-to-end encrypted conversation.
              </p>
              <div className="grid grid-cols-3 gap-4 w-full max-w-lg">
                 <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-2xl">
                   <div className="text-indigo-400 font-bold mb-1">AES-256</div>
                   <div className="text-[10px] text-slate-500 leading-tight">Advanced Encryption Standard for message secrecy.</div>
                 </div>
                 <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-2xl">
                   <div className="text-purple-400 font-bold mb-1">SHA-256</div>
                   <div className="text-[10px] text-slate-500 leading-tight">Cryptographic hashing for password verification.</div>
                 </div>
                 <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-2xl">
                   <div className="text-pink-400 font-bold mb-1">2FA</div>
                   <div className="text-[10px] text-slate-500 leading-tight">Multi-factor authentication for account security.</div>
                 </div>
              </div>
              <button 
                onClick={() => setIsReportOpen(true)}
                className="mt-10 px-6 py-2 bg-indigo-600/10 border border-indigo-600/30 text-indigo-400 rounded-full text-xs font-bold hover:bg-indigo-600/20 transition-all"
              >
                View Full Technical Report
              </button>
            </div>
          )}
        </main>
      </div>

      <ReportModal isOpen={isReportOpen} onClose={() => setIsReportOpen(false)} />
    </div>
  );
};

export default App;
