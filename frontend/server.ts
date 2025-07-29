import express from 'express';
import { join } from 'path';
import { spawn } from 'child_process';
import { watch } from 'fs';

const app = express();
const PORT = 8080;

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

app.listen(PORT, () => {
  console.log(`🌐 Frontend server running on http://localhost:${PORT}`);
  console.log(`👀 Watching for TypeScript changes...`);
});
