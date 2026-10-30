#!/usr/bin/env node
// `npx cortexterm`: start CortexTerm. The first run downloads the app for this machine from the
// official releases (the catalog), checks its checksum and unpacks it into ~/.cortexterm/app/<version>/;
// later runs start the installed app at once, without looking at the catalog: the app updates its
// frame and plugins itself, so a newer app release is only for machines that have none. The app runs
// on its own: closing the terminal does not quit it (its start output goes to ~/.cortexterm/logs/start.log).
// Arguments go to the app (`--headless`, `--safe`). `npx cortexterm runner` keeps it running without a
// window at every login (a LaunchAgent), for a Mac nobody sits at; `runner join <invitation>` joins
// that Mac to the network, `runner off` stops it.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, createWriteStream, existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const REPO = process.env.CORTEXTERM_REPO || 'agentbusiness/CortexTerm';
// CORTEXTERM_CATALOG: another catalog (a mirror, or a release under test).
const CATALOG_URL = process.env.CORTEXTERM_CATALOG || `https://github.com/${REPO}/releases/download/catalog/catalog.json`;
const HOME = process.env.CORTEX_HOME || join(homedir(), '.cortexterm');
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

// --- the runner: CortexTerm with no window, kept running on a Mac nobody sits at -------------------

const LABEL = 'com.cortexterm.runner';
const AGENT = join(homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
const RUNNER = join(HOME, 'runner', 'cortexterm.mjs');

const xml = (text) => String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** A LaunchAgent that starts this launcher (a copy kept in the home: npx's own is temporary) in
 * the foreground with `--headless` at every login, and again when the app ends with an error. */
function agentPlist() {
  const env = process.env.CORTEX_HOME ? `<key>EnvironmentVariables</key><dict><key>CORTEX_HOME</key><string>${xml(HOME)}</string></dict>` : '';
  const log = xml(join(HOME, 'logs', 'runner.log'));
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${LABEL}</string>
<key>ProgramArguments</key><array><string>${xml(process.execPath)}</string><string>${xml(RUNNER)}</string><string>--headless</string><string>--foreground</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>StandardOutPath</key><string>${log}</string>
<key>StandardErrorPath</key><string>${log}</string>
${env}
</dict></plist>
`;
}

function launchctl(args) {
  return new Promise((resolve) => {
    const child = spawn('/bin/launchctl', args, { stdio: 'ignore' });
    child.on('error', () => resolve(false));
    child.on('exit', (code) => resolve(code === 0));
  });
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
    if (!code) {
      say('npx cortexterm runner join <invitation>: the invitation from Settings > Mesh on a computer of your network');
      return 1;
    }
    const member = await frameCall('mesh.pair.join', { code });
    say(`joined the network as ${member.name}`);
    return 0;
  }
  if (process.platform !== 'darwin') {
    say('the runner is for Macs for now; elsewhere start CortexTerm with `npx cortexterm --headless`');
    return 1;
  }
  const domain = `gui/${process.getuid()}`;
  if (what === 'off') {
    await launchctl(['bootout', `${domain}/${LABEL}`]);
    rmSync(AGENT, { force: true });
    say('the runner is off: CortexTerm no longer starts at login, and the runner\'s CortexTerm has stopped');
    return 0;
  }
  if (what) {
    say(`unknown runner command \`${what}\` (runner, runner join <invitation>, runner off)`);
    return 1;
  }
  if (!(await ensureApp())) return 1;
  mkdirSync(join(HOME, 'runner'), { recursive: true });
  mkdirSync(join(HOME, 'logs'), { recursive: true });
  mkdirSync(join(homedir(), 'Library', 'LaunchAgents'), { recursive: true });
  writeFileSync(RUNNER, readFileSync(fileURLToPath(import.meta.url)));
  writeFileSync(AGENT, agentPlist());
  await launchctl(['bootout', `${domain}/${LABEL}`]);
  if (!(await launchctl(['bootstrap', domain, AGENT]))) {
    say(`cannot start the runner (launchctl bootstrap ${domain} ${AGENT} failed)`);
    return 1;
  }
  const pid = running();
  say(pid
    ? `CortexTerm is already running here (pid ${pid}); the runner keeps it running without a window from the next login`
    : 'the runner is on: CortexTerm runs here without a window, now and at every login');
  say('to join your network: npx cortexterm runner join <invitation>');
  return 0;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write([
      'npx cortexterm [--headless] [--safe]   start CortexTerm; the first run downloads it into ~/.cortexterm/app',
      'npx cortexterm runner                  keep CortexTerm running here without a window, at every login (macOS)',
      'npx cortexterm runner join <invitation>  join this computer to your network (the invitation from Settings > Mesh)',
      'npx cortexterm runner off              stop the runner',
      '',
    ].join('\n'));
    return 0;
  }
  if (args[0] === 'runner') return runner(args.slice(1));
  const pid = running();
  if (pid) {
    say(`CortexTerm is already running (pid ${pid})`);
    return 0;
  }
  const chosen = await ensureApp();
  if (!chosen) return 1;
  // The runner's LaunchAgent: the app in the foreground, so launchd sees it end.
  if (args.includes('--foreground')) {
    const child = spawn(executable(join(APPS, chosen)), args.filter((arg) => arg !== '--foreground'), { stdio: 'inherit' });
    return await new Promise((resolve) => {
      child.on('error', (error) => {
        say(`cannot start CortexTerm: ${error.message}`);
        resolve(1);
      });
      child.on('exit', (code) => resolve(code ?? 1));
    });
  }
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
