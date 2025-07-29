# RSA End-to-End Encrypted Chat App

A real-time chat application with RSA encryption built using TypeScript and Bun, running on a single unified server.

## Features

- 🔐 **End-to-End Encryption**: Messages are encrypted using RSA public key cryptography
- ⚡ **Real-time Messaging**: Powered by Socket.io for instant communication
- 🚀 **Fast Runtime**: Built with Bun for superior performance
- 📝 **TypeScript**: Fully typed for better development experience
- 💾 **In-Memory Storage**: No database required for demo purposes
- 🌐 **Unified Server**: Single server handles both API and frontend

## Architecture

### Unified Server (`server.ts`)
- Express.js server with TypeScript serving both API and static files
- Socket.io for real-time WebSocket connections
- RSA key pair generation using Node.js crypto module
- In-memory user and key storage
- CORS enabled for cross-origin requests
- Automatic TypeScript compilation with hot reload

### Frontend (`frontend/`)
- HTML + TypeScript client (auto-compiled to JavaScript)
- JSEncrypt library for browser-side RSA operations
- Real-time message encryption/decryption
- Debug interface with comprehensive logging

## Getting Started

### Prerequisites
- Bun runtime installed (`curl -fsSL https://bun.sh/install | bash`)

### Installation
```bash
bun install
```

### Running the Application

**Start the Unified Server** (Port 3000):
```bash
bun run dev
```

**Access the Application**:
- **Main Interface**: `http://localhost:3000`
- **Debug Interface**: `http://localhost:3000/debug`
- **API Endpoints**: `http://localhost:3000/api/*`

### Usage

1. **Register Users**: Enter a username and click "Register"
2. **Select Recipient**: Click on a user button to select them as message recipient
3. **Send Messages**: Type your message and click "Send" or press Enter
4. **View Encrypted Chat**: Messages are automatically encrypted and decrypted

## API Endpoints

- `POST /api/register` - Register a new user
- `GET /api/users` - Get list of all users
- `GET /api/public-key/:username` - Get public key for a user

## How RSA Encryption Works Here

1. **Key Generation**: Each user gets a unique RSA key pair (2048-bit)
2. **Message Encryption**: Messages are encrypted using the recipient's public key
3. **Message Decryption**: Only the recipient can decrypt using their private key
4. **Key Exchange**: Public keys are shared via the server, private keys stay client-side

## Development

- `bun run dev` - Start unified server with hot reload and auto-compilation
- `bun run start` - Start server in production mode
- `bun run build` - Build the application
- `bun run build-frontend` - Build frontend with watch mode

## File Structure

```
├── server.ts              # Unified server (API + Static files)
├── frontend/
│   ├── index.html         # Main interface
│   ├── debug.html         # Debug interface with logging
│   ├── main.ts           # TypeScript source
│   └── main.js           # Compiled JavaScript (auto-generated)
├── package.json
├── tsconfig.json
└── README.md
```
