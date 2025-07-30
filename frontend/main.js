// frontend/main.ts
var socket;
var myUsername = "";
var myPrivateKey = "";
var myPublicKey = "";
var users = [];
var selectedUser = "";
var publicKeys = {};
var keyStore;
var chat = document.getElementById("chat");
var usersDiv = document.getElementById("users");
var messageInput = document.getElementById("message");
var sendBtn = document.getElementById("send");
var registerBtn = document.getElementById("register");
var usernameInput = document.getElementById("username");
var logoutBtn = document.getElementById("logout");
var statusIndicator = document.getElementById("statusIndicator");
var registrationSection = document.getElementById("registrationSection");
var usersSection = document.getElementById("usersSection");
var messageInputArea = document.getElementById("messageInputArea");

class SecureKeyStorage {
  dbName = "ChatAppKeys";
  version = 1;
  storeName = "keystore";
  async openDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          const store = db.createObjectStore(this.storeName, { keyPath: "id" });
          store.createIndex("username", "username", { unique: false });
        }
      };
    });
  }
  async encryptData(data, password) {
    const encoder = new TextEncoder;
    const dataBuffer = encoder.encode(data);
    const passwordBuffer = encoder.encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      hash: "SHA-256"
    }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, dataBuffer);
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    return btoa(String.fromCharCode(...combined));
  }
  async decryptData(encryptedData, password) {
    try {
      const combined = new Uint8Array(atob(encryptedData).split("").map((char) => char.charCodeAt(0)));
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const encrypted = combined.slice(28);
      const encoder = new TextEncoder;
      const passwordBuffer = encoder.encode(password);
      const keyMaterial = await crypto.subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey({
        name: "PBKDF2",
        salt,
        iterations: 1e5,
        hash: "SHA-256"
      }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
      const decoder = new TextDecoder;
      return decoder.decode(decrypted);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Failed to decrypt data");
    }
  }
  getPassword(username) {
    const sessionId = sessionStorage.getItem("chat_session_id") || (() => {
      const id = `${username}_${Date.now()}_${Math.random()}`;
      sessionStorage.setItem("chat_session_id", id);
      return id;
    })();
    return `${sessionId}_${navigator.userAgent.slice(0, 50)}`;
  }
  async storePrivateKey(username, privateKey) {
    const db = await this.openDB();
    try {
      const encryptedKey = await this.encryptData(privateKey, this.getPassword(username));
      const transaction = db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      await new Promise((resolve, reject) => {
        const request = store.put({
          id: `${username}_private`,
          username,
          type: "private",
          encryptedData: encryptedKey,
          timestamp: Date.now()
        });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error("Transaction aborted"));
      });
    } finally {
      db.close();
    }
  }
  async getPrivateKey(username) {
    const db = await this.openDB();
    try {
      const transaction = db.transaction([this.storeName], "readonly");
      const store = transaction.objectStore(this.storeName);
      const result = await new Promise((resolve, reject) => {
        const request = store.get(`${username}_private`);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error("Transaction aborted"));
      });
      if (!result)
        return null;
      try {
        return await this.decryptData(result.encryptedData, this.getPassword(username));
      } catch {
        return null;
      }
    } finally {
      db.close();
    }
  }
  async storePublicKey(username, publicKey) {
    const db = await this.openDB();
    try {
      const transaction = db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      await new Promise((resolve, reject) => {
        const request = store.put({
          id: `${username}_public`,
          username,
          type: "public",
          data: publicKey,
          timestamp: Date.now()
        });
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error("Transaction aborted"));
      });
    } finally {
      db.close();
    }
  }
  async getPublicKey(username) {
    const db = await this.openDB();
    try {
      const transaction = db.transaction([this.storeName], "readonly");
      const store = transaction.objectStore(this.storeName);
      const result = await new Promise((resolve, reject) => {
        const request = store.get(`${username}_public`);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error("Transaction aborted"));
      });
      return result ? result.data : null;
    } finally {
      db.close();
    }
  }
  async clearKeys(username) {
    const db = await this.openDB();
    try {
      const transaction = db.transaction([this.storeName], "readwrite");
      const store = transaction.objectStore(this.storeName);
      await Promise.all([
        new Promise((resolve, reject) => {
          const request = store.delete(`${username}_private`);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        }),
        new Promise((resolve, reject) => {
          const request = store.delete(`${username}_public`);
          request.onsuccess = () => resolve();
          request.onerror = () => reject(request.error);
        })
      ]);
      await new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(new Error("Transaction aborted"));
      });
    } finally {
      db.close();
    }
  }
}
keyStore = new SecureKeyStorage;
function appendMessage(msg, isMine, isSystem = false) {
  const emptyState = chat.querySelector(".empty-state");
  if (emptyState) {
    emptyState.remove();
  }
  const div = document.createElement("div");
  div.className = `message ${isSystem ? "system" : isMine ? "mine" : "theirs"}`;
  if (isSystem) {
    div.textContent = msg;
  } else {
    const timestamp = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    div.innerHTML = `
      <div style="margin-bottom: 4px; font-size: 12px; opacity: 0.7;">
        ${isMine ? "You" : msg.split(":")[0]} • ${timestamp}
      </div>
      <div>${isMine ? msg.split(": ")[1] || msg : msg.split(": ").slice(1).join(": ") || msg}</div>
    `;
  }
  chat.appendChild(div);
  setTimeout(() => {
    chat.scrollTop = chat.scrollHeight;
  }, 10);
}
function updateConnectionStatus(connected) {
  if (connected) {
    statusIndicator.classList.add("connected");
    statusIndicator.title = "Connected";
  } else {
    statusIndicator.classList.remove("connected");
    statusIndicator.title = "Disconnected";
  }
}
async function fetchUsers() {
  try {
    console.log("\uD83D\uDC65 Fetching users list...");
    const res = await fetch("/api/users");
    if (!res.ok) {
      throw new Error("Failed to fetch users");
    }
    const usersList = await res.json();
    console.log("\uD83D\uDC65 Users fetched:", usersList);
    users = usersList;
    renderUsers();
  } catch (error) {
    console.error("❌ Error fetching users:", error);
    showStatusMessage("Failed to load users", "error");
  }
}
function showStatusMessage(message, type) {
  const existingStatus = document.querySelector(".status-message");
  if (existingStatus) {
    existingStatus.remove();
  }
  const statusDiv = document.createElement("div");
  statusDiv.className = `status-message status-${type}`;
  statusDiv.textContent = message;
  registrationSection.insertAdjacentElement("afterend", statusDiv);
  setTimeout(() => {
    if (statusDiv.parentNode) {
      statusDiv.remove();
    }
  }, 5000);
}
function renderUsers() {
  const otherUsers = users.filter((u) => u !== myUsername);
  if (otherUsers.length === 0) {
    usersDiv.innerHTML = '<p style="color: #64748b; font-style: italic;">No other users online. Open another tab to test!</p>';
    return;
  }
  usersDiv.innerHTML = otherUsers.map((u) => `<button class="user-btn ${selectedUser === u ? "selected" : ""}" onclick="selectUser('${u}')">
      \uD83D\uDC64 ${u}
    </button>`).join("");
}
function updateUIForLoggedInUser() {
  registrationSection.classList.add("hidden");
  usersSection.style.display = "block";
  messageInputArea.style.display = "block";
  logoutBtn.style.display = "inline-block";
  usernameInput.disabled = true;
  registerBtn.disabled = true;
}
function updateUIForLoggedOutUser() {
  registrationSection.classList.remove("hidden");
  usersSection.style.display = "none";
  messageInputArea.style.display = "none";
  logoutBtn.style.display = "none";
  usernameInput.disabled = false;
  registerBtn.disabled = false;
  messageInput.disabled = true;
  sendBtn.disabled = true;
}
window.selectUser = function(username) {
  selectedUser = username;
  renderUsers();
  messageInput.disabled = false;
  sendBtn.disabled = false;
  messageInput.placeholder = `Send encrypted message to ${username}...`;
  messageInput.focus();
  appendMessage(`Selected ${username} for secure messaging`, false, true);
};
registerBtn.onclick = async () => {
  const username = usernameInput.value.trim();
  if (!username) {
    showStatusMessage("Please enter a username", "error");
    usernameInput.focus();
    return;
  }
  if (username.length < 2) {
    showStatusMessage("Username must be at least 2 characters", "error");
    usernameInput.focus();
    return;
  }
  registerBtn.disabled = true;
  registerBtn.textContent = "Generating Keys...";
  try {
    if (!window.JSEncrypt) {
      throw new Error("JSEncrypt library not loaded");
    }
    console.log("\uD83D\uDD0D JSEncrypt library is available");
    console.log("\uD83D\uDD11 Generating RSA key pair...");
    const crypt = new window.JSEncrypt({ default_key_size: 2048 });
    crypt.getKey();
    myPrivateKey = crypt.getPrivateKey();
    myPublicKey = crypt.getPublicKey();
    if (!myPrivateKey || !myPublicKey) {
      throw new Error("Failed to generate RSA key pair");
    }
    console.log("✅ RSA key pair generated successfully");
    console.log("\uD83D\uDD11 Private key length:", myPrivateKey.length);
    console.log("\uD83D\uDD11 Public key length:", myPublicKey.length);
    console.log("\uD83D\uDCBE Storing keys securely...");
    await keyStore.storePrivateKey(username, myPrivateKey);
    await keyStore.storePublicKey(username, myPublicKey);
    console.log("✅ Keys stored successfully");
    registerBtn.textContent = "Joining...";
    console.log("\uD83D\uDCE1 Sending registration request...");
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, publicKey: myPublicKey })
    });
    console.log("\uD83D\uDCE1 Response status:", res.status);
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || "Registration failed");
    }
    const result = await res.json();
    console.log("\uD83D\uDCE1 Registration response:", result);
    myUsername = username;
    console.log("✅ Registration successful, keys stored securely");
    console.log("\uD83D\uDD0C Initializing Socket.io...");
    socket = window.io();
    socket.on("connect", () => {
      console.log("\uD83D\uDD0C Socket connected successfully");
      updateConnectionStatus(true);
      showStatusMessage(`Connected as ${username}`, "success");
      updateUIForLoggedInUser();
      fetchUsers();
    });
    socket.on("disconnect", () => {
      console.log("\uD83D\uDD0C Socket disconnected");
      updateConnectionStatus(false);
      showStatusMessage("Connection lost", "error");
    });
    socket.on("receive-message", async (payload) => {
      console.log("\uD83D\uDCE8 Received message:", payload);
      console.log("\uD83D\uDCE7 Message intended for:", payload.to, "| My username:", myUsername);
      if (payload.to !== myUsername) {
        console.log("❌ Message not for me, ignoring");
        return;
      }
      console.log("✅ Message is for me, attempting to decrypt");
      const storedPrivateKey = await keyStore.getPrivateKey(myUsername);
      if (!storedPrivateKey) {
        console.error("❌ No private key found in storage");
        appendMessage(`Failed to retrieve decryption key`, false, true);
        return;
      }
      console.log("\uD83D\uDD11 Retrieved private key from storage");
      const decrypt = new window.JSEncrypt;
      decrypt.setPrivateKey(storedPrivateKey);
      let decrypted = "";
      try {
        console.log("\uD83D\uDD13 Attempting decryption...");
        decrypted = decrypt.decrypt(payload.encrypted);
        if (!decrypted) {
          throw new Error("Decryption returned null");
        }
        console.log("✅ Decryption successful:", decrypted);
      } catch (error) {
        console.error("❌ Decryption failed:", error);
        decrypted = "[\uD83D\uDD12 Decryption failed]";
      }
      appendMessage(`${payload.from}: ${decrypted}`, false);
    });
  } catch (error) {
    console.error("Registration error:", error);
    const errorMessage = error instanceof Error ? error.message : "Registration failed";
    showStatusMessage(errorMessage, "error");
    registerBtn.disabled = false;
    registerBtn.textContent = "Join Chat";
  }
};
async function refreshUsers() {
  try {
    const res = await fetch("/api/users");
    users = await res.json();
    renderUsers();
    for (const u of users) {
      if (u !== myUsername && !publicKeys[u]) {
        try {
          const keyRes = await fetch(`/api/public-key/${u}`);
          if (keyRes.ok) {
            const data = await keyRes.json();
            publicKeys[u] = data.publicKey;
          }
        } catch (error) {
          console.error(`Failed to fetch public key for ${u}:`, error);
        }
      }
    }
  } catch (error) {
    console.error("Failed to refresh users:", error);
  }
}
sendBtn.onclick = async () => {
  if (!selectedUser) {
    showStatusMessage("Please select a user to chat with", "error");
    return;
  }
  const msg = messageInput.value.trim();
  if (!msg)
    return;
  sendBtn.disabled = true;
  sendBtn.textContent = "\uD83D\uDD04";
  try {
    let recipientPublicKey = await keyStore.getPublicKey(selectedUser);
    console.log("\uD83D\uDD11 Retrieved public key from storage for", selectedUser, ":", !!recipientPublicKey);
    if (!recipientPublicKey) {
      console.log("\uD83C\uDF10 Fetching public key from server for", selectedUser);
      const keyRes = await fetch(`/api/public-key/${selectedUser}`);
      if (keyRes.ok) {
        const data = await keyRes.json();
        recipientPublicKey = data.publicKey;
        console.log("✅ Retrieved public key from server:", !!recipientPublicKey);
        if (recipientPublicKey) {
          await keyStore.storePublicKey(selectedUser, recipientPublicKey);
          console.log("\uD83D\uDCBE Stored public key locally for future use");
        }
      } else {
        console.error("❌ Failed to fetch public key from server:", keyRes.status);
      }
    }
    if (!recipientPublicKey) {
      throw new Error("Could not find public key for recipient");
    }
    console.log("\uD83D\uDD10 Encrypting message with recipient public key...");
    const encrypt = new window.JSEncrypt;
    encrypt.setPublicKey(recipientPublicKey);
    const encrypted = encrypt.encrypt(msg);
    if (!encrypted) {
      throw new Error("Failed to encrypt message");
    }
    console.log("✅ Message encrypted successfully");
    console.log("\uD83D\uDCE4 Sending message via socket...");
    socket.emit("send-message", {
      to: selectedUser,
      from: myUsername,
      encrypted
    });
    console.log("\uD83D\uDCE4 Message sent via socket");
    appendMessage(`You: ${msg}`, true);
    messageInput.value = "";
    autoResizeTextarea(messageInput);
  } catch (error) {
    console.error("Send message error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    showStatusMessage("Failed to send message: " + errorMessage, "error");
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = "\uD83D\uDCE4";
    messageInput.focus();
  }
};
function autoResizeTextarea(textarea) {
  textarea.style.height = "auto";
  textarea.style.height = Math.min(textarea.scrollHeight, 120) + "px";
}
logoutBtn.onclick = async () => {
  if (confirm("Are you sure you want to logout? This will clear your encryption keys.")) {
    await logout();
  }
};
messageInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendBtn.click();
  }
});
messageInput.addEventListener("input", () => {
  autoResizeTextarea(messageInput);
});
usernameInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    registerBtn.click();
  }
});
async function logout() {
  if (myUsername) {
    try {
      await keyStore.clearKeys(myUsername);
      fetch("/api/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: myUsername })
      });
      console.log("✅ User logged out from server");
      console.log("Keys cleared from secure storage");
    } catch (error) {
      console.error("Failed to clear keys:", error);
    }
  }
  myUsername = "";
  myPrivateKey = "";
  myPublicKey = "";
  selectedUser = "";
  users = [];
  publicKeys = {};
  if (socket) {
    socket.disconnect();
  }
  updateUIForLoggedOutUser();
  updateConnectionStatus(false);
  usernameInput.value = "";
  messageInput.value = "";
  registerBtn.textContent = "Join Chat";
  chat.innerHTML = `
    <div class="empty-state">
      <div class="icon">\uD83D\uDCAC</div>
      <h3>Welcome to SecureChat</h3>
      <p>Your messages are protected with end-to-end encryption.<br>Register with a username to start chatting securely.</p>
    </div>
  `;
  const statusMessages = document.querySelectorAll(".status-message");
  statusMessages.forEach((msg) => msg.remove());
  showStatusMessage("Logged out successfully", "info");
}
window.addEventListener("beforeunload", async () => {
  await logout();
});
setInterval(() => {
  if (myUsername) {
    refreshUsers();
  }
}, 3000);
