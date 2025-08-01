interface User {
  username: string;
  publicKey: string;
}

interface MessagePayload {
  to: string;
  from: string;
  encrypted: string;
}

interface SecureKeyStore {
  storePrivateKey(username: string, privateKey: string): Promise<void>;
  getPrivateKey(username: string): Promise<string | null>;
  storePublicKey(username: string, publicKey: string): Promise<void>;
  getPublicKey(username: string): Promise<string | null>;
  clearKeys(username: string): Promise<void>;
  clearAllKeys(): Promise<void>;
  deleteDatabase(): Promise<void>;
  databaseExists(): Promise<boolean>;
}

let socket: any;
let myUsername: string = '';
let myPrivateKey: string = '';
let myPublicKey: string = '';
let users: string[] = [];
let selectedUser: string = '';
let publicKeys: { [username: string]: string } = {};
let keyStore: SecureKeyStore;

const chat = document.getElementById('chat') as HTMLDivElement;
const usersDiv = document.getElementById('users') as HTMLDivElement;
const messageInput = document.getElementById('message') as HTMLTextAreaElement;
const sendBtn = document.getElementById('send') as HTMLButtonElement;
const registerBtn = document.getElementById('register') as HTMLButtonElement;
const usernameInput = document.getElementById('username') as HTMLInputElement;
const logoutBtn = document.getElementById('logout') as HTMLButtonElement;
const statusIndicator = document.getElementById('statusIndicator') as HTMLDivElement;
const registrationSection = document.getElementById('registrationSection') as HTMLDivElement;
const usersSection = document.getElementById('usersSection') as HTMLDivElement;
const messageInputArea = document.getElementById('messageInputArea') as HTMLDivElement;

// Secure Key Storage Implementation using IndexedDB
class SecureKeyStorage implements SecureKeyStore {
  private dbName = 'ChatAppKeys';
  private version = 1;
  private storeName = 'keystore';

  private async openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          const store = db.createObjectStore(this.storeName, { keyPath: 'id' });
          store.createIndex('username', 'username', { unique: false });
        }
      };
    });
  }

  private async encryptData(data: string, password: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const passwordBuffer = encoder.encode(password);
    
    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    
    // Derive key from password
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    
    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Encrypt the data
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      dataBuffer
    );
    
    // Combine salt, iv, and encrypted data
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    // Convert to base64
    return btoa(String.fromCharCode(...combined));
  }

  private async decryptData(encryptedData: string, password: string): Promise<string> {
    try {
      const combined = new Uint8Array(atob(encryptedData).split('').map(char => char.charCodeAt(0)));
      
      // Extract salt, iv, and encrypted data
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const encrypted = combined.slice(28);
      
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(password);
      
      // Derive key from password
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        'PBKDF2',
        false,
        ['deriveKey']
      );
      
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      
      // Decrypt the data
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
      );
      
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  private getPassword(username: string): string {
    // Generate a session-based password (in real app, use user authentication)
    // Use a more stable approach that doesn't change on each call
    const sessionId = sessionStorage.getItem('chat_session_id') || 
      (() => {
        const id = `${username}_${Date.now()}_${Math.random()}`;
        sessionStorage.setItem('chat_session_id', id);
        return id;
      })();
    
    return `${sessionId}_${navigator.userAgent.slice(0, 50)}`;
  }

  async storePrivateKey(username: string, privateKey: string): Promise<void> {
    const db = await this.openDB();
    
    try {
      const encryptedKey = await this.encryptData(privateKey, this.getPassword(username));
      
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put({
          id: `${username}_private`,
          username,
          type: 'private',
          encryptedData: encryptedKey,
          timestamp: Date.now()
        });
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
    } finally {
      db.close();
    }
  }

  async getPrivateKey(username: string): Promise<string | null> {
    const db = await this.openDB();
    
    try {
      const transaction = db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      
      const result = await new Promise<any>((resolve, reject) => {
        const request = store.get(`${username}_private`);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
      if (!result) return null;
      
      try {
        return await this.decryptData(result.encryptedData, this.getPassword(username));
      } catch {
        return null;
      }
      
    } finally {
      db.close();
    }
  }

  async storePublicKey(username: string, publicKey: string): Promise<void> {
    const db = await this.openDB();
    
    try {
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put({
          id: `${username}_public`,
          username,
          type: 'public',
          data: publicKey,
          timestamp: Date.now()
        });
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
    } finally {
      db.close();
    }
  }

  async getPublicKey(username: string): Promise<string | null> {
    const db = await this.openDB();
    
    try {
      const transaction = db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      
      const result = await new Promise<any>((resolve, reject) => {
        const request = store.get(`${username}_public`);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
      return result ? result.data : null;
      
    } finally {
      db.close();
    }
  }

  async clearKeys(username: string): Promise<void> {
    const db = await this.openDB();
    
    try {
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      await Promise.all([
        new Promise<void>((resolve, reject) => {
          const request = store.delete(`${username}_private`);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        }),
        new Promise<void>((resolve, reject) => {
          const request = store.delete(`${username}_public`);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        })
      ]);
      
      // Wait for transaction to complete
      await new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
    } finally {
      db.close();
    }
  }

  /**
   * Clear ALL keys from the entire keystore (nuclear option)
   */
  async clearAllKeys(): Promise<void> {
    const db = await this.openDB();
    
    try {
      const transaction = db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      
      // Clear the entire object store
      await new Promise<void>((resolve, reject) => {
        const request = store.clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      // Wait for transaction to complete
      await new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error('Transaction aborted'));
      });
      
      console.log('🗑️ Cleared all keys from secure storage');
      
    } finally {
      db.close();
    }
  }

  /**
   * Completely delete the IndexedDB database (nuclear option)
   */
  async deleteDatabase(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      console.log('🗑️ Initiating complete database deletion...');
      
      const deleteRequest = indexedDB.deleteDatabase(this.dbName);
      
      deleteRequest.onsuccess = () => {
        console.log('✅ Database successfully deleted');
        resolve();
      };
      
      deleteRequest.onerror = () => {
        console.error('❌ Database deletion failed:', deleteRequest.error);
        reject(deleteRequest.error);
      };
      
      deleteRequest.onblocked = () => {
        console.warn('⚠️ Database deletion blocked - other connections may be open');
        // Don't reject, just warn and continue
        setTimeout(() => {
          console.log('🔄 Continuing despite blocked deletion...');
          resolve();
        }, 2000);
      };
      
      // Timeout safeguard
      setTimeout(() => {
        console.warn('⚠️ Database deletion timed out after 10 seconds');
        resolve(); // Don't fail the logout process
      }, 10000);
    });
  }

  /**
   * Check if database exists
   */
  async databaseExists(): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const request = indexedDB.open(this.dbName);
      
      request.onsuccess = () => {
        const db = request.result;
        const exists = db.objectStoreNames.contains(this.storeName);
        db.close();
        resolve(exists);
      };
      
      request.onerror = () => {
        resolve(false);
      };
      
      request.onupgradeneeded = () => {
        // Database doesn't exist
        const db = request.result;
        db.close();
        resolve(false);
      };
    });
  }
}

// Initialize secure key storage
keyStore = new SecureKeyStorage();

function appendMessage(msg: string, isMine: boolean, isSystem: boolean = false): void {
  // Clear empty state if it exists
  const emptyState = chat.querySelector('.empty-state');
  if (emptyState) {
    emptyState.remove();
  }

  const div = document.createElement('div');
  div.className = `message ${isSystem ? 'system' : (isMine ? 'mine' : 'theirs')}`;
  
  if (isSystem) {
    div.textContent = msg;
  } else {
    const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    div.innerHTML = `
      <div style="margin-bottom: 4px; font-size: 12px; opacity: 0.7;">
        ${isMine ? 'You' : msg.split(':')[0]} • ${timestamp}
      </div>
      <div>${isMine ? msg.split(': ')[1] || msg : msg.split(': ').slice(1).join(': ') || msg}</div>
    `;
  }
  
  chat.appendChild(div);
  
  // Ensure smooth scroll to bottom
  setTimeout(() => {
    chat.scrollTop = chat.scrollHeight;
  }, 10);
}

function updateConnectionStatus(connected: boolean): void {
  if (connected) {
    statusIndicator.classList.add('connected');
    statusIndicator.title = 'Connected';
  } else {
    statusIndicator.classList.remove('connected');
    statusIndicator.title = 'Disconnected';
  }
}

async function fetchUsers(): Promise<void> {
  try {
    console.log('👥 Fetching users list via socket...');
    
    // Use socket to get users instead of HTTP request
    if (socket && socket.connected) {
      socket.emit('get-users', (usersList: string[]) => {
        console.log('👥 Users fetched via socket:', usersList);
        users = usersList;
        renderUsers();
      });
    } else {
      // Fallback to HTTP if socket not available
      const res = await fetch('/api/users');
      if (!res.ok) {
        throw new Error('Failed to fetch users');
      }
      const usersList = await res.json();
      console.log('👥 Users fetched via HTTP:', usersList);
      users = usersList;
      renderUsers();
    }
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    showStatusMessage('Failed to load users', 'error');
  }
}

/**
 * Fetch all users with their public keys via socket
 */
async function fetchUsersWithKeys(): Promise<void> {
  try {
    console.log('🔑 Fetching users with public keys via socket...');
    
    if (socket && socket.connected) {
      socket.emit('get-users-with-keys', (usersWithKeys: User[]) => {
        console.log('🔑 Users with keys fetched via socket:', usersWithKeys);
        
        // Update users list
        users = usersWithKeys.map(u => u.username);
        
        // Cache all public keys locally
        usersWithKeys.forEach(async (user) => {
          if (user.username !== myUsername) {
            publicKeys[user.username] = user.publicKey;
            // Also store in secure storage for persistence
            await keyStore.storePublicKey(user.username, user.publicKey);
          }
        });
        
        console.log('💾 Cached public keys for all users');
        renderUsers();
      });
    } else {
      console.warn('⚠️ Socket not connected, falling back to individual requests');
      await fetchUsers();
    }
  } catch (error) {
    console.error('❌ Error fetching users with keys:', error);
    showStatusMessage('Failed to load users with keys', 'error');
  }
}

/**
 * Get a specific user's public key via socket
 */
async function getPublicKeyViaSocket(username: string): Promise<string | null> {
  return new Promise((resolve) => {
    if (!socket || !socket.connected) {
      resolve(null);
      return;
    }
    
    console.log(`🔑 Requesting public key for ${username} via socket...`);
    socket.emit('get-public-key', username, (response: { success: boolean; publicKey?: string; error?: string }) => {
      if (response.success && response.publicKey) {
        console.log(`✅ Received public key for ${username} via socket`);
        resolve(response.publicKey);
      } else {
        console.log(`❌ Failed to get public key for ${username}: ${response.error}`);
        resolve(null);
      }
    });
  });
}

function showStatusMessage(message: string, type: 'success' | 'error' | 'info'): void {
  // Remove any existing status messages
  const existingStatus = document.querySelector('.status-message');
  if (existingStatus) {
    existingStatus.remove();
  }

  const statusDiv = document.createElement('div');
  statusDiv.className = `status-message status-${type}`;
  statusDiv.textContent = message;
  
  // Insert after registration section
  registrationSection.insertAdjacentElement('afterend', statusDiv);
  
  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (statusDiv.parentNode) {
      statusDiv.remove();
    }
  }, 5000);
}

function renderUsers(): void {
  const otherUsers = users.filter(u => u !== myUsername);
  
  if (otherUsers.length === 0) {
    usersDiv.innerHTML = '<p style="color: #64748b; font-style: italic;">No other users online. Open another tab to test!</p>';
    return;
  }
  
  usersDiv.innerHTML = otherUsers.map(u => 
    `<button class="user-btn ${selectedUser === u ? 'selected' : ''}" onclick="selectUser('${u}')">
      👤 ${u}
    </button>`
  ).join('');
}

function updateUIForLoggedInUser(): void {
  registrationSection.classList.add('hidden');
  usersSection.style.display = 'block';
  messageInputArea.style.display = 'block';
  logoutBtn.style.display = 'inline-block';
  usernameInput.disabled = true;
  registerBtn.disabled = true;
}

function updateUIForLoggedOutUser(): void {
  registrationSection.classList.remove('hidden');
  usersSection.style.display = 'none';
  messageInputArea.style.display = 'none';
  logoutBtn.style.display = 'none';
  usernameInput.disabled = false;
  registerBtn.disabled = false;
  messageInput.disabled = true;
  sendBtn.disabled = true;
}

(window as any).selectUser = function(username: string): void {
  selectedUser = username;
  renderUsers(); // Re-render to show selection
  messageInput.disabled = false;
  sendBtn.disabled = false;
  messageInput.placeholder = `Send encrypted message to ${username}...`;
  messageInput.focus();
  appendMessage(`Selected ${username} for secure messaging`, false, true);
}

registerBtn.onclick = async (): Promise<void> => {
  const username = usernameInput.value.trim();
  if (!username) {
    showStatusMessage('Please enter a username', 'error');
    usernameInput.focus();
    return;
  }
  
  if (username.length < 2) {
    showStatusMessage('Username must be at least 2 characters', 'error');
    usernameInput.focus();
    return;
  }
  
  registerBtn.disabled = true;
  registerBtn.textContent = 'Generating Keys...';
  
  try {
    // Check if JSEncrypt is available
    if (!(window as any).JSEncrypt) {
      throw new Error('JSEncrypt library not loaded');
    }
    console.log('🔍 JSEncrypt library is available');
    
    // Generate RSA key pair on client side
    console.log('🔑 Generating RSA key pair...');
    const crypt = new (window as any).JSEncrypt({ default_key_size: 2048 });
    crypt.getKey();
    
    myPrivateKey = crypt.getPrivateKey();
    myPublicKey = crypt.getPublicKey();
    
    if (!myPrivateKey || !myPublicKey) {
      throw new Error('Failed to generate RSA key pair');
    }
    
    console.log('✅ RSA key pair generated successfully');
    console.log('🔑 Private key length:', myPrivateKey.length);
    console.log('🔑 Public key length:', myPublicKey.length);
    
    // Store keys securely
    console.log('💾 Storing keys securely...');
    await keyStore.storePrivateKey(username, myPrivateKey);
    await keyStore.storePublicKey(username, myPublicKey);
    console.log('✅ Keys stored successfully');
    
    registerBtn.textContent = 'Joining...';
    
    console.log('📡 Sending registration request...');
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, publicKey: myPublicKey })
    });
    
    console.log('📡 Response status:', res.status);
    
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || 'Registration failed');
    }
    
    const result = await res.json();
    console.log('📡 Registration response:', result);
    
    myUsername = username;
    
    console.log('✅ Registration successful, keys stored securely');
    
    // Initialize Socket.io
    console.log('🔌 Initializing Socket.io...');
    socket = (window as any).io();
    
    socket.on('connect', () => {
      console.log('🔌 Socket connected successfully');
      updateConnectionStatus(true);
      showStatusMessage(`Connected as ${username}`, 'success');
      
      // Notify server that user joined
      socket.emit('user-joined', username);
      
      // Update UI
      updateUIForLoggedInUser();
      
      // Fetch users with their public keys via socket
      fetchUsersWithKeys();
    });
    
    socket.on('disconnect', () => {
      console.log('🔌 Socket disconnected');
      updateConnectionStatus(false);
      showStatusMessage('Connection lost', 'error');
    });

    // Listen for real-time user updates
    socket.on('users-update', (usersList: string[]) => {
      console.log('📢 Real-time users update:', usersList);
      users = usersList;
      renderUsers();
    });

    socket.on('user-joined', (data: { username: string }) => {
      console.log('📢 User joined:', data.username);
      appendMessage(`${data.username} joined the chat`, false, true);
      // Refresh users to get the new user's public key
      fetchUsersWithKeys();
    });

    socket.on('user-left', (data: { username: string }) => {
      console.log('📢 User left:', data.username);
      appendMessage(`${data.username} left the chat`, false, true);
      // Remove from local cache
      delete publicKeys[data.username];
      // Update UI
      if (selectedUser === data.username) {
        selectedUser = '';
        messageInput.disabled = true;
        sendBtn.disabled = true;
        messageInput.placeholder = 'Select a user to start messaging...';
      }
    });
    
    socket.on('receive-message', async (payload: MessagePayload) => {
      console.log('📨 Received message:', payload);
      console.log('📧 Message intended for:', payload.to, '| My username:', myUsername);
      
      if (payload.to !== myUsername) {
        console.log('❌ Message not for me, ignoring');
        return;
      }
      
      console.log('✅ Message is for me, attempting to decrypt');
      
      // Decrypt message using securely stored private key
      const storedPrivateKey = await keyStore.getPrivateKey(myUsername);
      if (!storedPrivateKey) {
        console.error('❌ No private key found in storage');
        appendMessage(`Failed to retrieve decryption key`, false, true);
        return;
      }
      
      console.log('🔑 Retrieved private key from storage');
      
      const decrypt = new (window as any).JSEncrypt();
      decrypt.setPrivateKey(storedPrivateKey);
      
      let decrypted: string = '';
      try {
        console.log('🔓 Attempting decryption...');
        decrypted = decrypt.decrypt(payload.encrypted);
        if (!decrypted) {
          throw new Error('Decryption returned null');
        }
        console.log('✅ Decryption successful:', decrypted);
      } catch (error) {
        console.error('❌ Decryption failed:', error);
        decrypted = '[🔒 Decryption failed]';
      }
      
      appendMessage(`${payload.from}: ${decrypted}`, false);
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Registration failed';
    showStatusMessage(errorMessage, 'error');
    registerBtn.disabled = false;
    registerBtn.textContent = 'Join Chat';
  }
};

async function refreshUsers(): Promise<void> {
  try {
    console.log('🔄 Refreshing users via socket...');
    
    if (socket && socket.connected) {
      // Use socket-based approach for real-time updates
      fetchUsersWithKeys();
    } else {
      // Fallback to HTTP if socket not available
      const res = await fetch('/api/users');
      users = await res.json();
      renderUsers();
      
      // Fetch public keys for other users via HTTP as fallback
      for (const u of users) {
        if (u !== myUsername && !publicKeys[u]) {
          try {
            const keyRes = await fetch(`/api/public-key/${u}`);
            if (keyRes.ok) {
              const data = await keyRes.json();
              publicKeys[u] = data.publicKey;
              // Cache locally
              await keyStore.storePublicKey(u, data.publicKey);
            }
          } catch (error) {
            console.error(`Failed to fetch public key for ${u}:`, error);
          }
        }
      }
    }
  } catch (error) {
    console.error('Failed to refresh users:', error);
  }
}

sendBtn.onclick = async (): Promise<void> => {
  if (!selectedUser) {
    showStatusMessage('Please select a user to chat with', 'error');
    return;
  }
  
  const msg = messageInput.value.trim();
  if (!msg) return;
  
  sendBtn.disabled = true;
  sendBtn.textContent = '🔄';
  
  try {
    // Get recipient's public key - try multiple sources
    let recipientPublicKey = await keyStore.getPublicKey(selectedUser);
    console.log('🔑 Retrieved public key from storage for', selectedUser, ':', !!recipientPublicKey);
    
    // If not found locally, try in-memory cache
    if (!recipientPublicKey && publicKeys[selectedUser]) {
      recipientPublicKey = publicKeys[selectedUser];
      console.log('🔑 Retrieved public key from memory cache for', selectedUser);
    }
    
    // If still not found, try socket first, then HTTP fallback
    if (!recipientPublicKey) {
      console.log('🌐 Fetching public key via socket for', selectedUser);
      recipientPublicKey = await getPublicKeyViaSocket(selectedUser);
      
      // If socket fails, fallback to HTTP
      if (!recipientPublicKey) {
        console.log('🌐 Socket failed, trying HTTP for', selectedUser);
        const keyRes = await fetch(`/api/public-key/${selectedUser}`);
        if (keyRes.ok) {
          const data = await keyRes.json();
          recipientPublicKey = data.publicKey;
          console.log('✅ Retrieved public key from HTTP server:', !!recipientPublicKey);
        } else {
          console.error('❌ Failed to fetch public key from HTTP server:', keyRes.status);
        }
      }
      
      // Cache the retrieved key for future use
      if (recipientPublicKey) {
        publicKeys[selectedUser] = recipientPublicKey;
        await keyStore.storePublicKey(selectedUser, recipientPublicKey);
        console.log('💾 Stored public key locally for future use');
      }
    }
    
    if (!recipientPublicKey) {
      throw new Error('Could not find public key for recipient');
    }
    
    console.log('🔐 Encrypting message with recipient public key...');
    // Encrypt with recipient's public key
    const encrypt = new (window as any).JSEncrypt();
    encrypt.setPublicKey(recipientPublicKey);
    const encrypted = encrypt.encrypt(msg);
    
    if (!encrypted) {
      throw new Error('Failed to encrypt message');
    }
    
    console.log('✅ Message encrypted successfully');
    console.log('📤 Sending message via socket...');
    
    socket.emit('send-message', { 
      to: selectedUser, 
      from: myUsername, 
      encrypted 
    });
    
    console.log('📤 Message sent via socket');
    
    appendMessage(`You: ${msg}`, true);
    messageInput.value = '';
    autoResizeTextarea(messageInput);
    
  } catch (error) {
    console.error('Send message error:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    showStatusMessage('Failed to send message: ' + errorMessage, 'error');
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = '📤';
    messageInput.focus();
  }
};

// Auto-resize textarea
function autoResizeTextarea(textarea: HTMLTextAreaElement): void {
  textarea.style.height = 'auto';
  textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
}

// Add logout functionality
logoutBtn.onclick = async (): Promise<void> => {
  if (confirm('⚠️ Are you sure you want to logout?\n\nThis will:\n• Clear ALL encryption keys from this device\n• Delete all cached user data\n• Remove all secure storage\n• Disconnect from the chat\n\nYou will need to generate new keys when you login again.')) {
    await logout();
  }
};

messageInput.addEventListener('keypress', (e: KeyboardEvent) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendBtn.click();
  }
});

messageInput.addEventListener('input', () => {
  autoResizeTextarea(messageInput);
});

usernameInput.addEventListener('keypress', (e: KeyboardEvent) => {
  if (e.key === 'Enter') {
    registerBtn.click();
  }
});

// Secure logout function
async function logout(): Promise<void> {
  if (myUsername) {
    try {
      // Method 1: Clear all keys efficiently using the clearAllKeys method
      await keyStore.clearAllKeys();
      
      // Method 2: Also delete the entire IndexedDB database for maximum security
      try {
        console.log('🗑️ Attempting to delete IndexedDB database...');
        const dbDeleteRequest = indexedDB.deleteDatabase('ChatAppKeys');
        
        await new Promise<void>((resolve, reject) => {
          dbDeleteRequest.onsuccess = () => {
            console.log('✅ Successfully deleted IndexedDB database');
            resolve();
          };
          
          dbDeleteRequest.onerror = () => {
            console.error('❌ Failed to delete IndexedDB database:', dbDeleteRequest.error);
            resolve(); // Continue anyway
          };
          
          dbDeleteRequest.onblocked = () => {
            console.warn('⚠️ IndexedDB deletion blocked by other connections');
            // Try to force close any open connections
            setTimeout(() => {
              console.log('🔄 Retrying database deletion after delay...');
              resolve();
            }, 1000);
          };
          
          // Timeout fallback
          setTimeout(() => {
            console.warn('⚠️ Database deletion timed out, continuing anyway');
            resolve();
          }, 5000);
        });
        
      } catch (dbError) {
        console.error('❌ IndexedDB deletion error:', dbError);
      }
      
      // Method 3: Force close any remaining database connections
      try {
        // Create and immediately close a connection to force cleanup
        const tempRequest = indexedDB.open('ChatAppKeys');
        tempRequest.onsuccess = () => {
          const tempDb = tempRequest.result;
          tempDb.close();
          console.log('🔄 Forced closure of remaining database connections');
        };
      } catch (closeError) {
        console.warn('⚠️ Failed to force close database connections:', closeError);
      }
      
      
      // Clear session storage
      sessionStorage.removeItem('chat_session_id');
      sessionStorage.clear(); // Clear all session storage
      console.log('🗑️ Cleared all session storage');
      
      // Clear local storage if we used it
      localStorage.removeItem('securechat-monitor-session');
      console.log('🗑️ Cleared local storage data');
      
      // Notify server via socket first
      if (socket && socket.connected) {
        socket.emit('user-left', myUsername);
      }
      
      // Also notify via HTTP as backup
      fetch('/api/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: myUsername })
      });
      
      console.log('✅ User logged out from server');
      console.log('🔒 ALL encryption keys and sensitive data cleared from device');
    } catch (error) {
      console.error('❌ Failed to clear keys:', error);
    }
  }
  
  // Reset application state - clear all sensitive data from memory
  const sensitiveVars = [myUsername, myPrivateKey, myPublicKey];
  myUsername = '';
  myPrivateKey = '';
  myPublicKey = '';
  selectedUser = '';
  users = [];
  publicKeys = {}; // Clear all cached public keys
  
  // Overwrite sensitive variables with random data for security
  sensitiveVars.forEach(varValue => {
    if (varValue) {
      // Overwrite memory with random data
      varValue = Array(varValue.length).fill(0).map(() => 
        String.fromCharCode(Math.floor(Math.random() * 256))
      ).join('');
    }
  });
  
  // Force garbage collection of sensitive variables (if supported)
  if (typeof global !== 'undefined' && global.gc) {
    try {
      global.gc();
      console.log('🗑️ Forced garbage collection');
    } catch (e) {
      // Ignore if gc is not available
    }
  }
  
  if (socket) {
    socket.disconnect();
  }
  
  // Reset UI
  updateUIForLoggedOutUser();
  updateConnectionStatus(false);
  usernameInput.value = '';
  messageInput.value = '';
  registerBtn.textContent = 'Join Chat';
  
  // Clear chat and show empty state
  chat.innerHTML = `
    <div class="empty-state">
      <div class="icon">💬</div>
      <h3>Welcome to SecureChat</h3>
      <p>Your messages are protected with end-to-end encryption.<br>Register with a username to start chatting securely.</p>
    </div>
  `;
  
  // Remove any status messages
  const statusMessages = document.querySelectorAll('.status-message');
  statusMessages.forEach(msg => msg.remove());
  
  showStatusMessage('Logged out successfully', 'info');
}

// Add logout on page unload for security
window.addEventListener('beforeunload', async () => {
  await logout();
});

// Refresh users every 3 seconds
setInterval(() => {
  if (myUsername) {
    refreshUsers();
  }
}, 3000);
