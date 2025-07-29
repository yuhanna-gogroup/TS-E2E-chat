import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server, Socket } from 'socket.io';
import { generateKeyPairSync } from 'crypto';
import cors from 'cors';
import { join } from 'path';
import { spawn } from 'child_process';
import { watch } from 'fs';

interface User {
  publicKey: string;
  privateKey: string;
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

// In-memory user store: { username: { publicKey, privateKey } }
const users: Users = {};

// Generate RSA key pair
function generateKeyPair(): { publicKey: string; privateKey: string } {
  return generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

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
// Registration endpoint
app.post('/api/register', (req: Request, res: Response) => {
  const { username }: { username: string } = req.body;
  if (!username || users[username]) {
    return res.status(400).json({ error: 'Invalid or duplicate username' });
  }
  const { publicKey, privateKey } = generateKeyPair();
  users[username] = { publicKey, privateKey };
  res.json({ publicKey });
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

// Socket.io for real-time chat
io.on('connection', (socket: Socket) => {
  console.log('User connected:', socket.id);
  
  socket.on('send-message', (payload: MessagePayload) => {
    console.log('Message from', payload.from, 'to', payload.to, 'message:', payload.encrypted);
    // Forward encrypted message to recipient
    io.emit('receive-message', payload);
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
  console.log(`👀 Watching for TypeScript changes...`);
});
