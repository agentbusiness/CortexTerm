#!/usr/bin/env node
// `npx cortexterm`: start CortexTerm. The first run downloads the app for this machine from the
// official releases (the catalog), checks its checksum and unpacks it into ~/.cortexterm/app/<version>/;
// later runs start the installed app at once, without looking at the catalog: the app updates its
// frame and plugins itself, so a newer app release is only for machines that have none. The app runs
// on its own: closing the terminal does not quit it (its start output goes to ~/.cortexterm/logs/start.log).
// Arguments go to the app (`--headless`, `--safe`).

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, createWriteStream, existsSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';

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

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write('npx cortexterm [--headless] [--safe]\n\nStarts CortexTerm; the first run downloads it into ~/.cortexterm/app.\n');
    return 0;
  }
  const pid = running();
  if (pid) {
    say(`CortexTerm is already running (pid ${pid})`);
    return 0;
  }
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
    return 1;
  }
  prune(chosen);
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
