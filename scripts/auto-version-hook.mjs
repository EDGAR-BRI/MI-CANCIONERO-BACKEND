import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const PKG_PATH = path.resolve('package.json');

/**
 * Inspecciona el proceso ancestro de git commit
 * Compatible con Linux (/proc y ps), macOS (ps) y Windows (powershell)
 */
function findGitCommitCmdline() {
  // 1. Linux /proc (rápido y nativo en entornos Linux / WSL)
  try {
    let curr = process.ppid;
    while (curr && curr > 1) {
      if (fs.existsSync(`/proc/${curr}/cmdline`)) {
        const rawCmd = fs.readFileSync(`/proc/${curr}/cmdline`, 'utf8');
        if (rawCmd) {
          const cmdline = rawCmd.split('\0').filter(Boolean);
          const isGit = cmdline.some(arg => arg === 'git' || arg.endsWith('/git') || arg.endsWith('git.exe'));
          const isCommit = cmdline.includes('commit');
          if (isGit && isCommit) {
            return cmdline;
          }
        }
        const stat = fs.readFileSync(`/proc/${curr}/stat`, 'utf8').split(' ');
        curr = parseInt(stat[3], 10);
      } else {
        break;
      }
    }
  } catch {}

  // 2. macOS / BSD / POSIX fallback usando ps
  try {
    let curr = process.ppid;
    for (let i = 0; i < 6 && curr > 1; i++) {
      const out = execSync(`ps -p ${curr} -o ppid=,command=`, { encoding: 'utf8' }).trim();
      if (!out) break;
      const parts = out.split(/\s+/);
      const parentPid = parseInt(parts[0], 10);
      const cmdStr = out.slice(parts[0].length).trim();
      if (/\bgit(\.exe)?\b.*commit/.test(cmdStr)) {
        return cmdStr.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || cmdStr.split(' ');
      }
      curr = parentPid;
    }
  } catch {}

  // 3. Windows nativo (PowerShell)
  if (process.platform === 'win32') {
    try {
      const cmd = execSync(`powershell -NoProfile -Command "(Get-CimInstance Win32_Process -Filter \\"ProcessId = ${process.ppid}\\").CommandLine"`, { encoding: 'utf8' });
      if (cmd && /\bgit(\.exe)?\b.*commit/.test(cmd)) {
        return cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || cmd.split(' ');
      }
    } catch {}
  }

  return null;
}

/**
 * Extrae el mensaje de commit desde los argumentos de git
 */
function extractCommitMessage(cmdline) {
  if (!cmdline || !Array.isArray(cmdline)) return '';
  const clean = str => (str ? str.replace(/^["']|["']$/g, '').trim() : '');

  // 1. Flags -m o --message
  for (let i = 0; i < cmdline.length; i++) {
    const arg = cmdline[i];
    if (arg === '-m' || arg === '--message') {
      if (cmdline[i + 1]) return clean(cmdline[i + 1]);
    } else if (arg.startsWith('--message=')) {
      return clean(arg.slice('--message='.length));
    } else if (arg.startsWith('-m=')) {
      return clean(arg.slice(3));
    }
  }

  // 2. Flags -F o --file
  for (let i = 0; i < cmdline.length; i++) {
    const arg = cmdline[i];
    if (arg === '-F' || arg === '--file') {
      const filePath = clean(cmdline[i + 1]);
      if (filePath && fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8').trim();
      }
    } else if (arg.startsWith('--file=') || arg.startsWith('-F=')) {
      const filePath = clean(arg.split('=')[1]);
      if (filePath && fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8').trim();
      }
    }
  }

  return '';
}

function main() {
  try {
    if (!fs.existsSync(PKG_PATH)) return;

    // Si la versión ya fue modificada manualmente en el staging actual, no duplicar el incremento
    try {
      const stagedDiff = execSync('git diff --cached package.json', { encoding: 'utf8' });
      if (stagedDiff.includes('"version":')) {
        return;
      }
    } catch {
      // Ignorar si git diff falla
    }

    const cmdline = findGitCommitCmdline();
    let msg = extractCommitMessage(cmdline);

    msg = msg.trim();
    if (!msg) return;

    // Omitir commits automáticos de merge o revert
    if (msg.startsWith('Merge ') || msg.startsWith('Revert ')) {
      return;
    }

    // Mapeo de Conventional Commits a SemVer
    let bumpType = null;
    if (/^[a-z]+(\([^\)]+\))?!:/.test(msg) || /BREAKING CHANGE/i.test(msg)) {
      bumpType = 'major';
    } else if (/^feat(\([^\)]+\))?:/i.test(msg)) {
      bumpType = 'minor';
    } else if (/^(fix|style|perf|refactor)(\([^\)]+\))?:/i.test(msg)) {
      bumpType = 'patch';
    }

    if (!bumpType) {
      // chore, docs, test, build, ci, etc. no incrementan versión
      return;
    }

    const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
    if (!pkg.version) {
      pkg.version = '0.1.0';
    }

    const versionParts = pkg.version.split('-')[0].split('.').map(n => parseInt(n, 10) || 0);
    while (versionParts.length < 3) versionParts.push(0);
    const [maj, min, pat] = versionParts;

    let newVersion = pkg.version;
    if (bumpType === 'major') newVersion = `${maj + 1}.0.0`;
    else if (bumpType === 'minor') newVersion = `${maj}.${min + 1}.0`;
    else if (bumpType === 'patch') newVersion = `${maj}.${min}.${pat + 1}`;

    pkg.version = newVersion;
    fs.writeFileSync(PKG_PATH, JSON.stringify(pkg, null, 2) + '\n');
    execSync('git add package.json');

    console.log(`\n🚀 [AutoVersion] Mensaje detectado: "${msg.split('\n')[0]}"`);
    console.log(`📦 [AutoVersion] Versión actualizada a ${newVersion} (${bumpType.toUpperCase()}) en package.json.\n`);
  } catch (err) {
    // No interrumpir el flujo si ocurre algún error imprevisto
  }
}

main();
