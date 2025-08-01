import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import { join } from 'path';
import { spawn } from 'child_process';
import { watch } from 'fs';

interface User {
  publicKey: string;
}

interface Users {
  [username: string]: User;
}

interface MessagePayload {
  to: string;
  from: string;
  encrypted: string;
}

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json());

// In-memory user store: { username: { publicKey } }
const users: Users = {};

// Auto-compile TypeScript to JavaScript on file changes
function buildFrontend() {
  console.log('🔄 Building frontend...');
  const build = spawn('bun', ['build', 'frontend/main.ts', '--outfile', 'frontend/main.js'], {
    cwd: process.cwd(),
    stdio: 'inherit'
  });
  
  build.on('close', (code) => {
    if (code === 0) {
      console.log('✅ Frontend built successfully');
    } else {
      console.error('❌ Frontend build failed');
    }
  });
}

// Watch for TypeScript changes and rebuild
watch(join(process.cwd(), 'frontend/main.ts'), (eventType) => {
  if (eventType === 'change') {
    buildFrontend();
  }
});

// Initial build
buildFrontend();

// Serve static files from frontend directory
app.use(express.static(join(process.cwd(), 'frontend')));

// API Routes
// User registration endpoint
app.post('/api/register', (req, res) => {
  const { username, publicKey } = req.body;
  
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username is required' });
  }
  
  if (!publicKey || typeof publicKey !== 'string') {
    return res.status(400).json({ error: 'Public key is required' });
  }
  
  if (users[username]) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  // Store user with their client-generated public key
  users[username] = { publicKey };
  
  console.log(`User registered: ${username}`);
  
  res.json({ 
    message: 'User registered successfully'
  });
});

app.post('/api/logout', (req: Request, res: Response) => {
  const { username } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username is required' });
  }

  if (!users[username]) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Remove user from the in-memory store
  delete users[username];
  console.log(`User logged out: ${username}`);

  res.json({
    message: 'User logged out successfully'
  });
});

// Get all users (for demo)
app.get('/api/users', (req: Request, res: Response) => {
  res.json(Object.keys(users));
});

// Get public key for a user
app.get('/api/public-key/:username', (req: Request, res: Response) => {
  const user = users[req.params.username];
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ publicKey: user.publicKey });
});

// Serve main page
app.get('/', (req: Request, res: Response) => {
  res.sendFile(join(process.cwd(), 'frontend', 'index.html'));
});

// Serve debug page
app.get('/debug', (req: Request, res: Response) => {
  res.sendFile(join(process.cwd(), 'frontend', 'debug.html'));
});

// Serve monitor page
app.get('/monitor', (req: Request, res: Response) => {
  res.sendFile(join(process.cwd(), 'frontend', 'monitor.html'));
});

// Socket.io for real-time chat
io.on('connection', (socket: Socket) => {
  console.log('User connected:', socket.id);
  
  // Handle message sending
  socket.on('send-message', (payload: MessagePayload) => {
    console.log('📤 Message from', payload.from, 'to', payload.to);
    console.log('📧 Encrypted content:', payload.encrypted);
    // Forward encrypted message to recipient
    io.emit('receive-message', payload);
    console.log('📡 Message broadcasted to all clients');
  });

  // Handle request for all users with their public keys
  socket.on('get-users-with-keys', (callback) => {
    console.log('📋 Client requested users with public keys');
    const usersWithKeys = Object.entries(users).map(([username, user]) => ({
      username,
      publicKey: user.publicKey
    }));
    
    console.log(`📋 Sending ${usersWithKeys.length} users with public keys`);
    callback(usersWithKeys);
  });

  // Handle request for specific user's public key
  socket.on('get-public-key', (username: string, callback) => {
    console.log(`🔑 Client requested public key for: ${username}`);
    const user = users[username];
    
    if (user) {
      console.log(`✅ Found public key for ${username}`);
      callback({ success: true, publicKey: user.publicKey });
    } else {
      console.log(`❌ User ${username} not found`);
      callback({ success: false, error: 'User not found' });
    }
  });

  // Handle request for all usernames only
  socket.on('get-users', (callback) => {
    console.log('👥 Client requested users list');
    const usersList = Object.keys(users);
    console.log(`👥 Sending ${usersList.length} users:`, usersList);
    callback(usersList);
  });

  // Broadcast when a user joins (after registration)
  socket.on('user-joined', (username: string) => {
    console.log(`📢 Broadcasting user joined: ${username}`);
    socket.broadcast.emit('user-joined', { username });
    
    // Also broadcast updated users list to all clients
    const usersList = Object.keys(users);
    io.emit('users-update', usersList);
  });

  // Broadcast when a user leaves
  socket.on('user-left', (username: string) => {
    console.log(`📢 Broadcasting user left: ${username}`);
    socket.broadcast.emit('user-left', { username });
    
    // Also broadcast updated users list to all clients
    const usersList = Object.keys(users);
    io.emit('users-update', usersList);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Unified server running on http://localhost:${PORT}`);
  console.log(`📡 Socket.io ready for connections`);
  console.log(`🌐 Frontend available at http://localhost:${PORT}`);
  console.log(`🐛 Debug page at http://localhost:${PORT}/debug`);
  console.log(`� Monitor console at http://localhost:${PORT}/monitor`);
  console.log(`�👀 Watching for TypeScript changes...`);
});
