// Monitor Console - Message Flow Monitoring for Development
let socket = null;
let isConnected = false;
let messageCount = 0;
let encryptedCount = 0;
let socketEventCount = 0;
let userCount = 0;
let connectionStartTime = null;
let currentFilter = 'all';
let logEntries = [];

// DOM Elements
const connectBtn = document.getElementById('connectBtn');
const disconnectBtn = document.getElementById('disconnectBtn');
const clearBtn = document.getElementById('clearBtn');
const statusIndicator = document.getElementById('statusIndicator');
const monitorArea = document.getElementById('monitorArea');
const exportBtn = document.getElementById('exportBtn');
const saveSessionBtn = document.getElementById('saveSessionBtn');

// Stats elements
const totalMessagesEl = document.getElementById('totalMessages');
const encryptedMessagesEl = document.getElementById('encryptedMessages');
const socketEventsEl = document.getElementById('socketEvents');
const activeUsersEl = document.getElementById('activeUsers');
const connectionTimeEl = document.getElementById('connectionTime');

// Filter buttons
const filterBtns = document.querySelectorAll('.filter-btn');

/**
 * Initialize the monitoring console
 */
function initMonitor() {
  console.log('🔍 Initializing SecureChat Monitor Console');
  
  // Event listeners
  connectBtn.addEventListener('click', connectMonitor);
  disconnectBtn.addEventListener('click', disconnectMonitor);
  clearBtn.addEventListener('click', clearLog);
  exportBtn.addEventListener('click', exportLog);
  saveSessionBtn.addEventListener('click', saveSession);
  
  // Filter event listeners
  filterBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      setFilter(e.target.dataset.filter);
    });
  });
  
  updateUI();
}

/**
 * Connect to the monitoring socket
 */
function connectMonitor() {
  try {
    console.log('🔌 Connecting to monitoring socket...');
    
    socket = io();
    connectionStartTime = Date.now();
    
    socket.on('connect', () => {
      console.log('✅ Monitor connected to server');
      isConnected = true;
      updateConnectionStatus(true);
      addLogEntry('System connected to monitoring socket', 'system');
      
      // Start uptime counter
      startUptimeCounter();
    });
    
    socket.on('disconnect', () => {
      console.log('❌ Monitor disconnected from server');
      isConnected = false;
      updateConnectionStatus(false);
      addLogEntry('System disconnected from monitoring socket', 'error');
    });
    
    // Listen for all message traffic (this monitors the socket events)
    socket.onAny((eventName, ...args) => {
      handleSocketEvent(eventName, args);
    });
    
    // Listen for specific chat events
    socket.on('receive-message', (payload) => {
      handleEncryptedMessage(payload);
    });
    
    socket.on('user-joined', (data) => {
      handleUserEvent('User joined', data);
    });
    
    socket.on('user-left', (data) => {
      handleUserEvent('User left', data);
    });
    
    socket.on('users-update', (users) => {
      userCount = users.length;
      updateStats();
      addLogEntry(`Users update: ${users.length} active users - [${users.join(', ')}]`, 'user-event');
    });

    // Monitor new socket events for user and key management
    socket.on('get-users-with-keys', (callback) => {
      addLogEntry('Client requested all users with public keys', 'socket-event');
    });

    socket.on('get-public-key', (username, callback) => {
      addLogEntry(`Client requested public key for user: ${username}`, 'socket-event');
    });

    socket.on('get-users', (callback) => {
      addLogEntry('Client requested users list', 'socket-event');
    });

    // Monitor client-to-server events by intercepting emit calls
    const originalEmit = socket.emit;
    socket.emit = function(eventName, ...args) {
      // Log outgoing events for monitoring
      handleOutgoingSocketEvent(eventName, args);
      return originalEmit.apply(this, arguments);
    };
    
  } catch (error) {
    console.error('❌ Failed to connect monitor:', error);
    addLogEntry(`Failed to connect: ${error.message}`, 'error');
  }
}

/**
 * Disconnect from monitoring socket
 */
function disconnectMonitor() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
  isConnected = false;
  connectionStartTime = null;
  updateConnectionStatus(false);
  addLogEntry('Monitor disconnected manually', 'system');
}

/**
 * Handle any socket event for comprehensive monitoring
 */
function handleSocketEvent(eventName, args) {
  // Skip some noisy events
  if (['connect', 'disconnect', 'ping', 'pong'].includes(eventName)) {
    return;
  }
  
  const timestamp = new Date().toISOString();
  const logData = {
    timestamp,
    event: eventName,
    direction: 'incoming',
    data: args,
    type: 'socket-event'
  };
  
  console.log('📡 Incoming Socket Event:', logData);
  
  // Add to internal log
  logEntries.push(logData);
  
  // Increment socket event counter
  socketEventCount++;
  updateStats();
  
  // Display specific incoming events
  switch(eventName) {
    case 'users-update':
      // Already handled above
      break;
    case 'user-joined':
      // Already handled above  
      break;
    case 'user-left':
      // Already handled above
      break;
    default:
      addLogEntry(`📡 Incoming Event: ${eventName}`, 'socket-event', {
        'Event Name': eventName,
        'Direction': 'Server → Client',
        'Data': JSON.stringify(args).substring(0, 200)
      });
  }
}
function handleOutgoingSocketEvent(eventName, args) {
  // Skip some noisy events
  if (['connect', 'disconnect', 'ping', 'pong'].includes(eventName)) {
    return;
  }
  
  const timestamp = new Date().toISOString();
  const logData = {
    timestamp,
    event: eventName,
    direction: 'outgoing',
    data: args,
    type: 'socket-event'
  };
  
  console.log('� Outgoing Socket Event:', logData);
  
  // Add to internal log
  logEntries.push(logData);
  
  // Increment socket event counter for outgoing events too
  socketEventCount++;
  updateStats();
  
  // Display in monitor based on event type
  switch(eventName) {
    case 'get-users-with-keys':
      addLogEntry('📋 Request: Get all users with public keys', 'socket-event', {
        'Event Type': 'User Management',
        'Direction': 'Client → Server',
        'Description': 'Requesting bulk user data with public keys'
      });
      break;
      
    case 'get-public-key':
      const username = args[0];
      addLogEntry(`🔑 Request: Get public key for "${username}"`, 'socket-event', {
        'Event Type': 'Key Management',
        'Direction': 'Client → Server',
        'Target User': username,
        'Description': 'Requesting specific user\'s public key'
      });
      break;
      
    case 'get-users':
      addLogEntry('👥 Request: Get users list', 'socket-event', {
        'Event Type': 'User Management',
        'Direction': 'Client → Server',
        'Description': 'Requesting list of active usernames'
      });
      break;
      
    case 'user-joined':
      const joinedUser = args[0];
      addLogEntry(`📢 Broadcast: User "${joinedUser}" joined`, 'user-event', {
        'Event Type': 'User Status',
        'Direction': 'Client → Server',
        'User': joinedUser,
        'Action': 'Join notification'
      });
      break;
      
    case 'user-left':
      const leftUser = args[0];
      addLogEntry(`📢 Broadcast: User "${leftUser}" left`, 'user-event', {
        'Event Type': 'User Status',
        'Direction': 'Client → Server',
        'User': leftUser,
        'Action': 'Leave notification'
      });
      break;
      
    case 'send-message':
      const messagePayload = args[0];
      messageCount++;
      encryptedCount++;
      updateStats();
      
      addLogEntry('📤 Outgoing encrypted message', 'encrypted', {
        'From': messagePayload.from,
        'To': messagePayload.to,
        'Size': `${messagePayload.encrypted.length} characters`,
        'Direction': 'Client → Server',
        'Encrypted Data': messagePayload.encrypted
      });
      break;
      
    default:
      addLogEntry(`📡 Socket Event: ${eventName}`, 'socket-event', {
        'Event Name': eventName,
        'Direction': 'Client → Server',
        'Arguments': JSON.stringify(args).substring(0, 200)
      });
  }
}

/**
 * Handle encrypted message monitoring
 */
function handleEncryptedMessage(payload) {
  messageCount++;
  encryptedCount++;
  updateStats();
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    type: 'encrypted-message',
    from: payload.from,
    to: payload.to,
    encrypted: payload.encrypted,
    size: payload.encrypted ? payload.encrypted.length : 0
  };
  
  logEntries.push(logEntry);
  
  addLogEntry(
    `Encrypted message intercepted`,
    'encrypted',
    {
      'From': payload.from,
      'To': payload.to,
      'Size': `${logEntry.size} characters`,
      'Encrypted Data': payload.encrypted
    }
  );
  
  console.log('🔒 Encrypted Message Intercepted:', logEntry);
}

/**
 * Handle user events
 */
function handleUserEvent(action, data) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    type: 'user-event',
    action,
    data
  };
  
  logEntries.push(logEntry);
  addLogEntry(`${action}: ${JSON.stringify(data)}`, 'user-event');
}

/**
 * Add a log entry to the monitor display
 */
function addLogEntry(message, type = 'info', details = null) {
  // Clear empty state if it exists
  const emptyState = monitorArea.querySelector('.empty-state');
  if (emptyState) {
    emptyState.remove();
  }
  
  const logDiv = document.createElement('div');
  logDiv.className = `log-entry log-${type}`;
  
  const timestamp = new Date().toLocaleTimeString();
  
  let content = `
    <div class="log-timestamp">${timestamp}</div>
    <div class="log-message">${message}</div>
  `;
  
  if (details) {
    content += '<div class="message-details">';
    for (const [key, value] of Object.entries(details)) {
      content += `
        <div class="message-label">${key}:</div>
        <div class="message-value">
          ${key === 'Encrypted Data' ? 
            `<div class="encrypted-data">${value.substring(0, 200)}${value.length > 200 ? '...' : ''}</div>` : 
            value
          }
        </div>
      `;
    }
    content += '</div>';
  }
  
  logDiv.innerHTML = content;
  
  // Apply filter
  logDiv.style.display = shouldShowEntry(type) ? 'block' : 'none';
  
  monitorArea.appendChild(logDiv);
  
  // Auto-scroll to bottom
  monitorArea.scrollTop = monitorArea.scrollHeight;
  
  // Limit log entries to prevent memory issues
  const maxEntries = 1000;
  const entries = monitorArea.querySelectorAll('.log-entry');
  if (entries.length > maxEntries) {
    entries[0].remove();
  }
}

/**
 * Update connection status UI
 */
function updateConnectionStatus(connected) {
  const statusSpan = statusIndicator.querySelector('span');
  
  if (connected) {
    statusSpan.className = 'status-connected';
    statusSpan.textContent = 'Connected';
    connectBtn.style.display = 'none';
    disconnectBtn.style.display = 'inline-block';
  } else {
    statusSpan.className = 'status-disconnected';
    statusSpan.textContent = 'Disconnected';
    connectBtn.style.display = 'inline-block';
    disconnectBtn.style.display = 'none';
  }
}

/**
 * Update statistics display
 */
function updateStats() {
  totalMessagesEl.textContent = messageCount;
  encryptedMessagesEl.textContent = encryptedCount;
  socketEventsEl.textContent = socketEventCount;
  activeUsersEl.textContent = userCount;
}

/**
 * Start uptime counter
 */
function startUptimeCounter() {
  const updateUptime = () => {
    if (connectionStartTime && isConnected) {
      const uptime = Date.now() - connectionStartTime;
      const minutes = Math.floor(uptime / 60000);
      const seconds = Math.floor((uptime % 60000) / 1000);
      connectionTimeEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    } else {
      connectionTimeEl.textContent = '--:--';
    }
  };
  
  setInterval(updateUptime, 1000);
}

/**
 * Set log filter
 */
function setFilter(filter) {
  currentFilter = filter;
  
  // Update button states
  filterBtns.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });
  
  // Show/hide log entries
  const entries = monitorArea.querySelectorAll('.log-entry');
  entries.forEach(entry => {
    const type = Array.from(entry.classList).find(cls => cls.startsWith('log-'))?.replace('log-', '');
    entry.style.display = shouldShowEntry(type) ? 'block' : 'none';
  });
}

/**
 * Check if log entry should be shown based on current filter
 */
function shouldShowEntry(type) {
  if (currentFilter === 'all') return true;
  
  switch (currentFilter) {
    case 'messages':
      return type === 'encrypted';
    case 'users':
      return type === 'user-event';
    case 'socket-events':
      return type === 'socket-event';
    case 'key-management':
      return type === 'socket-event' || type === 'encrypted'; // Key-related events
    case 'errors':
      return type === 'error';
    default:
      return true;
  }
}

/**
 * Clear the log display
 */
function clearLog() {
  monitorArea.innerHTML = `
    <div class="empty-state">
      <div style="font-size: 48px; margin-bottom: 15px;">📡</div>
      <h3>Log Cleared</h3>
      <p>Monitoring continues... New events will appear here</p>
    </div>
  `;
  
  logEntries = [];
  messageCount = 0;
  encryptedCount = 0;
  socketEventCount = 0;
  updateStats();
}

/**
 * Export log data
 */
function exportLog() {
  const exportData = {
    timestamp: new Date().toISOString(),
    stats: {
      totalMessages: messageCount,
      encryptedMessages: encryptedCount,
      socketEvents: socketEventCount,
      activeUsers: userCount,
      connectionTime: connectionTimeEl.textContent
    },
    logs: logEntries
  };
  
  const dataStr = JSON.stringify(exportData, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  
  const link = document.createElement('a');
  link.href = URL.createObjectURL(dataBlob);
  link.download = `securechat-monitor-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
  link.click();
  
  addLogEntry('Log data exported successfully', 'system');
}

/**
 * Save current session
 */
function saveSession() {
  const sessionData = {
    timestamp: new Date().toISOString(),
    stats: {
      totalMessages: messageCount,
      encryptedMessages: encryptedCount,
      socketEvents: socketEventCount,
      activeUsers: userCount,
      uptime: connectionTimeEl.textContent
    },
    logEntries: logEntries.slice(-100), // Last 100 entries
    isConnected
  };
  
  localStorage.setItem('securechat-monitor-session', JSON.stringify(sessionData));
  addLogEntry('Session saved to local storage', 'system');
}

/**
 * Update UI elements
 */
function updateUI() {
  updateConnectionStatus(isConnected);
  updateStats();
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initMonitor);

// Add some diagnostic info
console.log('🔍 SecureChat Monitor Console Loaded');
console.log('📡 This tool monitors encrypted message traffic for development and security testing');
console.log('🔒 All intercepted messages remain encrypted and cannot be read without private keys');
