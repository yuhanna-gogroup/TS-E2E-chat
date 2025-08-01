# SecureChat Function Documentation

## Overview
This document provides comprehensive documentation for all functions in the SecureChat application, which implements end-to-end encrypted messaging using RSA encryption and secure key storage.

## Table of Contents
- [Core Classes](#core-classes)
- [UI Functions](#ui-functions)
- [Authentication Functions](#authentication-functions)
- [Messaging Functions](#messaging-functions)
- [Utility Functions](#utility-functions)
- [Event Handlers](#event-handlers)

---

## Core Classes

### `SecureKeyStorage`
Secure key storage implementation using IndexedDB with AES-GCM encryption.

#### Private Methods

##### `openDB(): Promise<IDBDatabase>`
**Purpose**: Opens an IndexedDB connection and creates the object store if needed.
**Returns**: Promise that resolves to an IDBDatabase instance
**Throws**: Error if database opening fails
**Usage**: Internal method for database access

##### `encryptData(data: string, password: string): Promise<string>`
**Purpose**: Encrypts data using AES-GCM with PBKDF2 key derivation.
**Parameters**: 
- `data`: The plaintext data to encrypt
- `password`: The password for key derivation
**Returns**: Promise that resolves to base64-encoded encrypted data
**Throws**: Error if encryption fails
**Security**: Uses 100,000 PBKDF2 iterations with SHA-256

##### `decryptData(encryptedData: string, password: string): Promise<string>`
**Purpose**: Decrypts data encrypted with encryptData method.
**Parameters**:
- `encryptedData`: Base64-encoded encrypted data
- `password`: The password used for encryption
**Returns**: Promise that resolves to decrypted plaintext
**Throws**: Error if decryption fails or password is incorrect

##### `getPassword(username: string): string`
**Purpose**: Generates a session-based password for encryption/decryption.
**Parameters**: `username`: The username to generate password for
**Returns**: A stable session-based password string
**Note**: Uses sessionStorage to maintain consistency across the session

#### Public Methods

##### `storePrivateKey(username: string, privateKey: string): Promise<void>`
**Purpose**: Stores a private key in encrypted form in IndexedDB.
**Parameters**:
- `username`: The username associated with the key
- `privateKey`: The RSA private key in PEM format
**Returns**: Promise that resolves when storage is complete
**Throws**: Error if storage fails or encryption fails

##### `getPrivateKey(username: string): Promise<string | null>`
**Purpose**: Retrieves and decrypts a private key from IndexedDB.
**Parameters**: `username`: The username associated with the key
**Returns**: Promise that resolves to the decrypted private key or null if not found
**Throws**: Error if database access fails

##### `storePublicKey(username: string, publicKey: string): Promise<void>`
**Purpose**: Stores a public key in plain text in IndexedDB.
**Parameters**:
- `username`: The username associated with the key
- `publicKey`: The RSA public key in PEM format
**Returns**: Promise that resolves when storage is complete
**Throws**: Error if storage fails

##### `getPublicKey(username: string): Promise<string | null>`
**Purpose**: Retrieves a public key from IndexedDB.
**Parameters**: `username`: The username associated with the key
**Returns**: Promise that resolves to the public key or null if not found
**Throws**: Error if database access fails

##### `clearKeys(username: string): Promise<void>`
**Purpose**: Removes both private and public keys for a username from IndexedDB.
**Parameters**: `username`: The username whose keys should be deleted
**Returns**: Promise that resolves when deletion is complete
**Throws**: Error if deletion fails

---

## UI Functions

### `appendMessage(msg: string, isMine: boolean, isSystem: boolean = false): void`
**Purpose**: Appends a message to the chat interface with proper styling and timestamps.
**Parameters**:
- `msg`: The message content to display
- `isMine`: Whether the message was sent by the current user
- `isSystem`: Whether this is a system message (optional, default: false)
**Features**: Automatically scrolls to bottom, removes empty state, adds timestamps

### `updateConnectionStatus(connected: boolean): void`
**Purpose**: Updates the visual connection status indicator in the header.
**Parameters**: `connected`: True if connected, false if disconnected
**Effect**: Changes status indicator color and tooltip

### `showStatusMessage(message: string, type: 'success' | 'error' | 'info'): void`
**Purpose**: Displays a temporary status message to the user.
**Parameters**:
- `message`: The message text to display
- `type`: The message type ('success', 'error', or 'info')
**Behavior**: Automatically removes the message after 5 seconds

### `renderUsers(): void`
**Purpose**: Renders the list of online users (excluding current user) as clickable buttons.
**Features**: Shows message if no other users are online, highlights selected user

### `updateUIForLoggedInUser(): void`
**Purpose**: Updates the UI to show the logged-in state.
**Actions**: Hides registration form, shows chat interface, enables controls

### `updateUIForLoggedOutUser(): void`
**Purpose**: Updates the UI to show the logged-out state.
**Actions**: Shows registration form, hides chat interface, disables controls

---

## Authentication Functions

### `registerBtn.onclick = async (): Promise<void>`
**Purpose**: Handles user registration process including key generation and server communication.
**Process**:
1. Validates username input
2. Generates RSA key pair (2048-bit)
3. Stores keys securely in IndexedDB
4. Registers with server API
5. Initializes Socket.io connection
6. Sets up message handlers
**Returns**: Promise that resolves when registration is complete or rejects on error

### `logout(): Promise<void>`
**Purpose**: Securely logs out the user by clearing all data and resetting the application state.
**Actions**:
- Clears encryption keys from storage
- Resets all global variables
- Disconnects Socket.io
- Updates UI to logged-out state
- Shows empty state in chat
**Returns**: Promise that resolves when logout is complete

---

## Messaging Functions

### `sendBtn.onclick = async (): Promise<void>`
**Purpose**: Handles sending encrypted messages to the selected user.
**Process**:
1. Validates user selection and message content
2. Retrieves recipient's public key
3. Encrypts message with RSA public key
4. Sends encrypted message via Socket.io
5. Displays sent message in chat
**Returns**: Promise that resolves when message is sent or rejects on error

### `fetchUsers(): Promise<void>`
**Purpose**: Fetches the list of online users from the server API.
**Actions**: Updates global users array, refreshes UI
**Returns**: Promise that resolves when users are fetched and UI is updated

### `refreshUsers(): Promise<void>`
**Purpose**: Refreshes the users list from the server and fetches public keys for new users.
**Features**: Caches public keys locally for faster encryption
**Returns**: Promise that resolves when refresh is complete

---

## Utility Functions

### `autoResizeTextarea(textarea: HTMLTextAreaElement): void`
**Purpose**: Auto-resizes a textarea based on its content.
**Parameters**: `textarea`: The textarea element to resize
**Behavior**: Prevents excessive height by capping at 120px

### `selectUser(username: string): void`
**Purpose**: Selects a user for messaging and updates the UI accordingly.
**Parameters**: `username`: The username to select for messaging
**Actions**: Enables message input, updates placeholder text, shows selection

---

## Event Handlers

### Message Input Events
- **Enter Key**: Sends message (Shift+Enter for new line)
- **Input**: Auto-resizes textarea

### Username Input Events  
- **Enter Key**: Triggers registration

### Logout Handler
- **Click**: Shows confirmation dialog before logout

### Socket.io Event Handlers

#### `connect`
**Purpose**: Handles successful Socket.io connection
**Actions**: Updates status, shows success message, fetches users

#### `disconnect`
**Purpose**: Handles Socket.io disconnection
**Actions**: Updates status, shows error message

#### `receive-message`
**Purpose**: Handles incoming encrypted messages
**Process**:
1. Validates message is for current user
2. Retrieves private key from secure storage
3. Decrypts message using RSA private key
4. Displays decrypted message in chat

---

## Security Features

### Encryption
- **RSA 2048-bit**: For message encryption/decryption
- **AES-256-GCM**: For private key storage encryption
- **PBKDF2**: Key derivation with 100,000 iterations

### Key Management
- **Client-side generation**: Private keys never leave the client
- **Secure storage**: Private keys encrypted in IndexedDB
- **Session-based passwords**: Stable encryption for storage

### End-to-End Encryption Flow
1. Each user generates RSA key pair locally
2. Public keys shared with server for routing
3. Private keys encrypted and stored locally
4. Messages encrypted with recipient's public key
5. Messages decrypted with recipient's private key
6. Server only sees encrypted messages

---

## Error Handling

All async functions include comprehensive error handling:
- Database errors are caught and logged
- Encryption/decryption failures are handled gracefully
- Network errors show user-friendly messages
- Invalid input is validated before processing

## Performance Optimizations

- **Key caching**: Public keys cached locally
- **Lazy loading**: Database connections opened as needed
- **Efficient scrolling**: Smooth scroll behavior with timeouts
- **Auto-refresh**: Users list updated every 3 seconds
- **Memory management**: Database connections properly closed
