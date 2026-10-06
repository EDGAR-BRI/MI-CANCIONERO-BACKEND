import fs from 'node:fs';
import path from 'node:path';

const hookPath = path.resolve('.git/hooks/pre-commit');
const scriptContent = `#!/usr/bin/env bash

# Auto-versionador basado en Conventional Commits
if [ -f "scripts/auto-version-hook.mjs" ]; then
  exec node scripts/auto-version-hook.mjs
elif [ -f "scripts/auto-version-hook.js" ]; then
  exec node scripts/auto-version-hook.js
fi
`;

try {
  const hooksDir = path.resolve('.git/hooks');
  if (fs.existsSync(hooksDir)) {
    fs.writeFileSync(hookPath, scriptContent, { mode: 0o755 });
    console.log('✓ [AutoVersion] Hook pre-commit instalado en .git/hooks/pre-commit');
  }
} catch (e) {
  // Ignorar en entornos de despliegue donde no exista .git
}
