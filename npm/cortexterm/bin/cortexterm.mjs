#!/usr/bin/env node
// `npx cortexterm`: start CortexTerm. The first run downloads the app for this machine from the
// official releases (the catalog), checks its checksum and unpacks it into ~/.cortexterm/app/<version>/;
// later runs start the installed app at once, without looking at the catalog: the app updates its
// frame and plugins itself, so a newer app release is only for machines that have none. The app runs
// on its own: closing the terminal does not quit it (its start output goes to ~/.cortexterm/logs/start.log).
// Arguments go to the app (`--headless`, `--safe`). `npx cortexterm runner` keeps it running without
// a local chat model: launchd on macOS, systemd on Linux (boot and SSH logout). `runner join <invitation>`
// joins the mesh, `runner off` stops it. Development uses the same installer via ./cortexterm runner.
// Every desktop start also puts a CortexTerm starter in /Applications (Linux: the app menu).

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, chmodSync, closeSync, constants, createWriteStream, existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pipeline } from 'node:stream/promises';

const REPO = process.env.CORTEXTERM_REPO || 'agentbusiness/CortexTerm';
// CORTEXTERM_CATALOG: another catalog (a mirror, or a release under test).
const CATALOG_URL = process.env.CORTEXTERM_CATALOG || `https://github.com/${REPO}/releases/download/catalog/catalog.json`;
const HOME = resolve(process.env.CORTEX_HOME || join(homedir(), '.cortexterm'));
const DEV_ROOT = process.env.CORTEXTERM_DEV_ROOT ? resolve(process.env.CORTEXTERM_DEV_ROOT) : null;
const APPS = join(HOME, 'app');
const READY = '.ready';
const START_LOG = join(HOME, 'logs', 'start.log');
const KEEP = 2;

const say = (text) => process.stderr.write(`cortexterm: ${text}\n`);

function platform() {
  const key = `${process.platform}-${process.arch}`;
  const known = { 'darwin-arm64': 'darwin-arm64', 'linux-x64': 'linux-x64', 'linux-arm64': 'linux-arm64' };
  if (!known[key]) throw new Error(`CortexTerm runs on Apple Silicon Macs and on Linux (x64, arm64), not on ${key}`);
  return known[key];
}

/** `0.3.7` as a comparable triple, or null. */
function version(text) {
  const match = /^v?(\d+)\.(\d+)\.(\d+)(\+.*)?$/.exec(String(text ?? '').trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function compare(a, b) {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/** The response to a GET of `url`, after redirects (GitHub sends release files from another host). */
function get(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const request = client.get(url, { headers: { 'user-agent': 'cortexterm-npx' } }, (response) => {
      const status = response.statusCode ?? 0;
      if (status >= 300 && status < 400 && response.headers.location && redirects > 0) {
        response.resume();
        resolve(get(new URL(response.headers.location, url).toString(), redirects - 1));
        return;
      }
      if (status !== 200) {
        response.resume();
        reject(new Error(`${url} answered ${status}`));
        return;
      }
      resolve(response);
    });
    request.on('error', reject);
  });
}

/** The release catalog: the current version of the app and every part, with their files. */
async function catalog() {
  const response = await fetch(CATALOG_URL, { headers: { 'user-agent': 'cortexterm-npx' } });
  if (!response.ok) throw new Error(`${CATALOG_URL} answered ${response.status}`);
  const parsed = await response.json();
  if (parsed.format !== 'cortexterm-catalog/1') throw new Error(`unknown catalog format ${parsed.format}`);
  return parsed;
}

/** Installed app versions, newest first. */
function installed() {
  if (!existsSync(APPS)) return [];
  return readdirSync(APPS)
    .filter((name) => version(name) && existsSync(join(APPS, name, READY)))
    .sort((a, b) => compare(version(b), version(a)));
}

function executable(dir) {
  return process.platform === 'darwin' ? join(dir, 'CortexTerm.app', 'Contents', 'MacOS', 'CortexTerm') : join(dir, 'cortexterm', 'CortexTerm');
}

/** Download the app archive, check size and SHA-256, unpack it beside the others. */
async function install(app, asset) {
  mkdirSync(APPS, { recursive: true });
  const archive = join(APPS, `.download-${app.version}.tar.gz`);
  const staging = join(APPS, `.staging-${app.version}`);
  say(`downloading CortexTerm ${app.version} (${Math.round(asset.size / 1e6)} MB)`);
  // node:http rather than fetch: fetch's stream fails when a server closes the connection while the
  // file write is behind.
  const body = await get(asset.url);
  const hash = createHash('sha256');
  let received = 0;
  let reported = 0;
  body.on('data', (chunk) => {
    hash.update(chunk);
    received += chunk.length;
    const percent = asset.size ? Math.floor((received * 100) / asset.size) : 0;
    if (percent >= reported + 10) {
      reported = percent;
      process.stderr.write(`\rcortexterm: ${percent}%`);
    }
  });
  await pipeline(body, createWriteStream(archive));
  process.stderr.write('\n');
  if (received !== asset.size || hash.digest('hex') !== String(asset.sha256).toLowerCase()) {
    rmSync(archive, { force: true });
    throw new Error(`${asset.name} does not match the catalog (size or checksum); it was not used`);
  }
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  await run('tar', ['-xzf', archive, '-C', staging]);
  rmSync(archive, { force: true });
  const target = join(APPS, app.version);
  rmSync(target, { recursive: true, force: true });
  renameSync(staging, target);
  writeFileSync(join(target, READY), '');
  say(`CortexTerm ${app.version} is installed in ${target}`);
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'ignore', 'inherit'] });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${command} failed (${code})`))));
  });
}

/** The pid of a CortexTerm running for this home, if any (the frame writes run/frame.json). */
function running() {
  try {
    const { pid } = JSON.parse(readFileSync(join(HOME, 'run', 'frame.json'), 'utf8'));
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

/** Keep the newest versions (and the one starting now). */
function prune(keep) {
  installed()
    .slice(KEEP)
    .filter((name) => name !== keep)
    .forEach((name) => rmSync(join(APPS, name), { recursive: true, force: true }));
}

/** The installed app to start (downloaded first on a machine that has none), or null. */
async function ensureApp() {
  const key = platform();
  // The installed app updates itself (frame and plugins): only a machine without one downloads.
  if (installed().length === 0) {
    try {
      const listed = await catalog();
      const files = listed.app?.files?.[key];
      if (listed.app && files?.archive) await install(listed.app, files.archive);
      else say(`no CortexTerm app is released for ${key} yet`);
    } catch (error) {
      say(`cannot download CortexTerm (${error.message})`);
    }
  }
  const chosen = installed()[0];
  if (!chosen) {
    say('CortexTerm is not installed and could not be downloaded');
    return null;
  }
  prune(chosen);
  return chosen;
}

/** Old installed launch frames cannot parse --runner, even when a newer frame is staged.
 * Refresh the bootstrap app in that case before installing a persistent service. */
async function runnerApp() {
  let chosen = await ensureApp();
  if (!chosen) return null;
  let app = executable(join(APPS, chosen));
  if ((await serviceCommand(app, ['--help'], true)).stdout.includes('--runner')) return app;
  say('the installed app predates the runner profile; downloading the current app');
  const listed = await catalog();
  const asset = listed.app?.files?.[platform()]?.archive;
  if (!asset) throw new Error('the release catalog has no runner-capable app for this machine yet');
  await install(listed.app, asset);
  chosen = listed.app.version;
  app = executable(join(APPS, chosen));
  if (!(await serviceCommand(app, ['--help'], true)).stdout.includes('--runner')) {
    throw new Error('the released app does not support --runner yet; it needs frame 0.1.12 or later');
  }
  return app;
}

// The service starts the installed frame directly, independently of npx's temporary cache.
const LABEL = 'com.cortexterm.runner';
const AGENT = join(homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
const SERVICE = 'cortexterm-runner.service';
const SYSTEM_SERVICE = process.platform === 'linux' && process.getuid() === 0;
const UNIT_DIR = SYSTEM_SERVICE ? '/etc/systemd/system' : join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'systemd', 'user');
const UNIT = join(UNIT_DIR, SERVICE);
const xml = (value) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function serviceEnv() {
  const env = { CORTEX_HOME: HOME, HOME: homedir(), PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin' };
  if (DEV_ROOT) { env.CORTEXTERM_DEV_ROOT = DEV_ROOT; env.CORTEX_NO_HANDOVER = '1'; }
  if (process.env.SHELL) env.SHELL = process.env.SHELL;
  // Preserve explicit release mirrors for offline/private installations.
  for (const key of ['CORTEXTERM_REPO', 'CORTEXTERM_CATALOG', 'CORTEX_LOG']) {
    if (process.env[key]) env[key] = process.env[key];
  }
  return env;
}

function agentPlist(app) {
  const env = Object.entries(serviceEnv()).map(([key, value]) => `<key>${xml(key)}</key><string>${xml(value)}</string>`).join('');
  const log = xml(join(HOME, 'logs', 'runner.log'));
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${LABEL}</string>
<key>ProgramArguments</key><array><string>${xml(app)}</string><string>--runner</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>AbandonProcessGroup</key><true/>
<key>StandardOutPath</key><string>${log}</string>
<key>StandardErrorPath</key><string>${log}</string>
<key>EnvironmentVariables</key><dict>${env}</dict>
</dict></plist>
`;
}

// systemd interprets percent specifiers and, in ExecStart, dollar expansion even inside quotes.
function unitQuote(value, command = false) {
  const text = String(value);
  if (/[\0\r\n]/.test(text)) throw new Error('service paths and environment values cannot contain line breaks or NUL');
  return '"' + text.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, command ? '$$$$' : '$$') + '"';
}

function serviceUnit(app) {
  const env = Object.entries(serviceEnv()).map(([key, value]) => `Environment=${unitQuote(`${key}=${value}`)}`).join('\n');
  return `[Unit]
Description=CortexTerm model-free runner
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${unitQuote(app, true)} --runner
${env}
Restart=always
RestartSec=5
# The frame shuts down its plugins; cortexd and its shells deliberately survive a service restart.
KillMode=process
TimeoutStopSec=90
UMask=0077

[Install]
WantedBy=${SYSTEM_SERVICE ? 'multi-user.target' : 'default.target'}
`;
}

function serviceCommand(command, args, capture = false) {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    const env = { ...process.env };
    if (process.platform === 'linux' && process.getuid() !== 0 && command === 'systemctl') {
      env.XDG_RUNTIME_DIR ||= `/run/user/${process.getuid()}`;
      env.DBUS_SESSION_BUS_ADDRESS ||= `unix:path=${env.XDG_RUNTIME_DIR}/bus`;
    }
    const child = spawn(command, args, { env, stdio: ['ignore', capture ? 'pipe' : 'ignore', 'pipe'] });
    child.stdout?.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => resolve({ ok: false, stdout, stderr: error.message }));
    child.on('exit', (code) => resolve({ ok: code === 0, stdout: stdout.trim(), stderr: stderr.trim() }));
  });
}

const systemctl = (args, capture = false) => serviceCommand('systemctl', [...(SYSTEM_SERVICE ? [] : ['--user']), '--no-ask-password', ...args], capture);

async function requireService(result, action) {
  const outcome = await result;
  if (!outcome.ok) throw new Error(`${action}: ${outcome.stderr || 'service manager unavailable'}`);
  return outcome;
}

async function waitForRunner() {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const info = JSON.parse(readFileSync(join(HOME, 'run', 'frame.json'), 'utf8'));
      const response = await fetch(`http://127.0.0.1:${info.port}/health`, { signal: AbortSignal.timeout(Math.max(1, Math.min(1000, deadline - Date.now()))) });
      const health = await response.json();
      if (health.ok && health.runner && health.pid === info.pid) return info.pid;
    } catch { /* The installed frame may still be starting. */ }
    await new Promise((resolve) => setTimeout(resolve, Math.min(500, Math.max(0, deadline - Date.now()))));
  }
  throw new Error(`the runner did not become ready in 60 seconds; inspect ${join(HOME, 'logs', 'runner.log')} or journalctl ${SYSTEM_SERVICE ? '' : '--user '} -u ${SERVICE}`);
}

/** The frame's API token: in the Keychain on macOS, in `run/frame.json` elsewhere. */
function frameToken(info) {
  if (info.token) return Promise.resolve(info.token);
  return new Promise((resolve, reject) => {
    let out = '';
    const child = spawn('/usr/bin/security', ['find-generic-password', '-s', 'CortexTerm frame token', '-a', HOME, '-w'], { stdio: ['ignore', 'pipe', 'ignore'] });
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve(out.trim()) : reject(new Error('the frame token is not in the Keychain'))));
  });
}

/** One call on the running frame (`POST /api/rpc`), as scripts make it. */
async function frameCall(method, params) {
  let info;
  try {
    info = JSON.parse(readFileSync(join(HOME, 'run', 'frame.json'), 'utf8'));
    process.kill(info.pid, 0);
  } catch {
    throw new Error('CortexTerm is not running here: start it first (npx cortexterm runner)');
  }
  const token = await frameToken(info);
  const response = await fetch(`http://127.0.0.1:${info.port}/api/rpc?token=${encodeURIComponent(token)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method, params }),
  });
  const answer = await response.json();
  if (!answer.ok) throw new Error(answer.error?.message ?? JSON.stringify(answer.error));
  return answer.result;
}

async function runner(args) {
  const [what, ...rest] = args;
  if (what === 'join') {
    const code = rest.join(' ').trim();
    if (!code) throw new Error('runner join <invitation>: use the invitation from Settings > Mesh on another computer');
    const member = await frameCall('mesh.pair.join', { code });
    say(`joined the network as ${member.name}`);
    return 0;
  }
  if (!['darwin', 'linux'].includes(process.platform)) throw new Error('the runner supports macOS and Linux');
  if (what === 'off') {
    if (process.platform === 'darwin') {
      const job = `gui/${process.getuid()}/${LABEL}`;
      if ((await serviceCommand('/bin/launchctl', ['print', job])).ok) {
        await requireService(serviceCommand('/bin/launchctl', ['bootout', job]), 'cannot stop the runner');
      }
      rmSync(AGENT, { force: true });
    } else {
      const installed = existsSync(UNIT);
      const active = await systemctl(['is-active', '--quiet', SERVICE]);
      if (installed || active.ok) {
        await requireService(systemctl(['stop', SERVICE]), 'cannot stop the runner');
        if (installed) await requireService(systemctl(['disable', SERVICE]), 'cannot disable the runner');
        rmSync(UNIT, { force: true });
        await requireService(systemctl(['daemon-reload']), 'cannot reload services');
      }
    }
    say('the runner is off; existing terminal shells are preserved');
    return 0;
  }
  if (what) throw new Error(`unknown runner command ${what}; use runner, runner join <invitation>, or runner off`);
  if (running()) {
    // Do not take over a desktop or another checkout sharing this home.
    throw new Error('CortexTerm already runs for this home; stop it before installing the runner');
  }
  let app;
  if (DEV_ROOT) {
    if (!existsSync(join(DEV_ROOT, 'cortexterm'))) throw new Error(`no development launcher in ${DEV_ROOT}`);
    await run(join(DEV_ROOT, 'cortexterm'), ['--build-only']);
    app = process.platform === 'darwin'
      ? join(DEV_ROOT, 'build', 'CortexTerm.app', 'Contents', 'MacOS', 'CortexTerm')
      : join(DEV_ROOT, 'build', 'cortexterm', 'CortexTerm');
  } else {
    app = await runnerApp();
    if (!app) return 1;
  }
  if (process.platform === 'linux' && !SYSTEM_SERVICE) {
    // Linger keeps the user manager alive after SSH logout and starts it at boot.
    const linger = await serviceCommand('loginctl', ['show-user', String(process.getuid()), '--property=Linger', '--value'], true);
    if (linger.stdout !== 'yes') {
      await requireService(serviceCommand('loginctl', ['--no-ask-password', 'enable-linger', String(process.getuid())]),
        `cannot keep the runner alive after logout; an administrator must run loginctl enable-linger ${process.getuid()}`);
    }
  }
  mkdirSync(join(HOME, 'logs'), { recursive: true, mode: 0o700 });
  if (process.platform === 'darwin') {
    mkdirSync(dirname(AGENT), { recursive: true });
    writeFileSync(AGENT, agentPlist(app));
    const domain = `gui/${process.getuid()}`;
    await serviceCommand('/bin/launchctl', ['bootout', `${domain}/${LABEL}`]);
    await requireService(serviceCommand('/bin/launchctl', ['bootstrap', domain, AGENT]), 'cannot start the runner');
  } else {
    mkdirSync(UNIT_DIR, { recursive: true });
    writeFileSync(UNIT, serviceUnit(app));
    await requireService(systemctl(['daemon-reload']), 'cannot load the runner service');
    await requireService(systemctl(['enable', SERVICE]), 'cannot enable the runner');
    await requireService(systemctl(['restart', SERVICE]), 'cannot start the runner');
  }
  const pid = await waitForRunner();
  say(`the ${DEV_ROOT ? 'development ' : ''}runner is on (pid ${pid}): no local model, background updates, automatic restarts`);
  say(process.platform === 'darwin' ? 'starts at login; you can close this terminal' : 'starts at boot and stays running after SSH logout');
  return 0;
}

// The app starter: CortexTerm in /Applications (~/Applications when that is not writable) on macOS, a
// .desktop entry on Linux, so the app starts from Launchpad, Spotlight or the app menu. It starts the
// newest app installed in ~/.cortexterm/app (npx cortexterm when there is none), or in development this
// checkout's ./cortexterm. Every start writes it again, only where it changed.
const sh = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

function starterScript() {
  const lines = ['#!/bin/sh', `export PATH=${sh(process.env.PATH || '/usr/local/bin:/usr/bin:/bin')}`, `export CORTEX_HOME=${sh(HOME)}`];
  const log = sh(START_LOG);
  lines.push(`mkdir -p ${sh(dirname(START_LOG))}`);
  if (DEV_ROOT) {
    lines.push(`exec ${sh(join(DEV_ROOT, 'cortexterm'))} >>${log} 2>&1`);
  } else {
    const app = process.platform === 'darwin' ? 'CortexTerm.app/Contents/MacOS/CortexTerm' : 'cortexterm/CortexTerm';
    lines.push(
      `apps=${sh(APPS)}`,
      'for v in $(ls "$apps" 2>/dev/null | grep -E \'^[0-9]+\\.[0-9]+\\.[0-9]+$\' | sort -t. -k1,1nr -k2,2nr -k3,3nr); do',
      `  [ -f "$apps/$v/${READY}" ] && exec "$apps/$v/${app}" >>${log} 2>&1`,
      'done',
      `exec npx --yes cortexterm >>${log} 2>&1`,
    );
  }
  return `${lines.join('\n')}\n`;
}

/** Write `content` to `path` when it differs; true when it was written. */
function place(path, content, mode) {
  try {
    if (readFileSync(path).equals(Buffer.from(content))) return false;
  } catch { /* Not there yet. */ }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, mode ? { mode } : undefined);
  if (mode) chmodSync(path, mode);
  return true;
}

/** The app icon: this checkout's, or the newest installed app's. */
function starterIcon(name) {
  if (DEV_ROOT) return join(DEV_ROOT, 'ui', 'shell', 'assets', name);
  const chosen = installed()[0];
  if (!chosen) return null;
  return process.platform === 'darwin'
    ? join(APPS, chosen, 'CortexTerm.app', 'Contents', 'Resources', name)
    : join(APPS, chosen, 'cortexterm', 'ui', 'shell', 'assets', name);
}

function writable(dir) {
  try { accessSync(dir, constants.W_OK); return true; } catch { return false; }
}

function installStarter() {
  try {
    if (process.platform === 'darwin') {
      const folder = writable('/Applications') ? '/Applications' : join(homedir(), 'Applications');
      const contents = join(folder, 'CortexTerm.app', 'Contents');
      const icon = starterIcon('CortexTerm.icns');
      const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>CortexTerm</string>
<key>CFBundleDisplayName</key><string>CortexTerm</string>
<key>CFBundleIdentifier</key><string>ai.cortexterm.starter</string>
<key>CFBundleExecutable</key><string>CortexTerm</string>
<key>CFBundleIconFile</key><string>CortexTerm.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
`;
      let changed = place(join(contents, 'Info.plist'), plist);
      changed = place(join(contents, 'MacOS', 'CortexTerm'), starterScript(), 0o755) || changed;
      if (icon && existsSync(icon)) changed = place(join(contents, 'Resources', 'CortexTerm.icns'), readFileSync(icon)) || changed;
      if (changed) say(`CortexTerm is in ${folder}`);
    } else if (process.platform === 'linux') {
      const script = join(HOME, 'starter', 'cortexterm');
      const iconSource = starterIcon('cortexterm-512.png');
      const icon = join(HOME, 'starter', 'cortexterm.png');
      if (iconSource && existsSync(iconSource)) place(icon, readFileSync(iconSource));
      place(script, starterScript(), 0o755);
      const apps = join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'applications');
      const entry = `[Desktop Entry]
Type=Application
Name=CortexTerm
Comment=AI terminal with a local model
Exec="${script.replace(/(["`$\\])/g, '\\$1')}"
Icon=${icon}
Terminal=false
Categories=System;TerminalEmulator;Development;
StartupWMClass=CortexTerm
`;
      if (place(join(apps, 'cortexterm.desktop'), entry)) say(`CortexTerm is in the app menu (${apps})`);
    }
  } catch (error) {
    say(`cannot install the app starter (${error.message})`);
  }
}

async function foreground(args) {
  const appArgs = args.filter((arg) => arg !== '--foreground');
  let command;
  if (DEV_ROOT) {
    command = join(DEV_ROOT, 'cortexterm');
  } else {
    const chosen = await ensureApp();
    if (!chosen) return 1;
    command = executable(join(APPS, chosen));
  }
  installStarter();
  return await new Promise((resolve) => {
    const child = spawn(command, appArgs, { stdio: 'inherit' });
    const forward = (signal) => { if (child.exitCode === null) child.kill(signal); };
    const term = () => forward('SIGTERM');
    const interrupt = () => forward('SIGINT');
    process.on('SIGTERM', term);
    process.on('SIGINT', interrupt);
    const done = (code) => {
      process.off('SIGTERM', term);
      process.off('SIGINT', interrupt);
      resolve(code);
    };
    child.once('error', (error) => { say(`cannot start CortexTerm: ${error.message}`); done(1); });
    child.once('exit', (code) => done(code ?? 1));
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write([
      'npx cortexterm [--headless] [--safe]   start CortexTerm; the first run downloads it into ~/.cortexterm/app',
      'npx cortexterm runner                  model-free background service (macOS login / Linux boot)',
      'npx cortexterm runner join <invitation>  join this computer to your network (the invitation from Settings > Mesh)',
      'npx cortexterm runner off              stop the runner',
      '',
    ].join('\n'));
    return 0;
  }
  if (args[0] === 'runner') return runner(args.slice(1));
  if (args[0] === 'starter') {
    installStarter();
    return 0;
  }
  if (args.includes('--foreground')) return foreground(args);
  const pid = running();
  if (pid) {
    installStarter();
    say(`CortexTerm is already running (pid ${pid})`);
    return 0;
  }
  const chosen = await ensureApp();
  if (!chosen) return 1;
  installStarter();
  // Its own session, detached from this terminal: closing the terminal does not quit it.
  mkdirSync(join(HOME, 'logs'), { recursive: true });
  const log = openSync(START_LOG, 'a');
  const child = spawn(executable(join(APPS, chosen)), args, { detached: true, stdio: ['ignore', log, log] });
  closeSync(log);
  return await new Promise((resolve) => {
    child.on('error', (error) => {
      say(`cannot start CortexTerm: ${error.message}`);
      resolve(1);
    });
    child.on('spawn', () => {
      child.unref();
      say(`CortexTerm ${chosen} is starting; you can close this terminal (start output: ${START_LOG})`);
      resolve(0);
    });
  });
}

main().then(
  (code) => process.exit(code),
  (error) => {
    say(error.message);
    process.exit(1);
  },
);
