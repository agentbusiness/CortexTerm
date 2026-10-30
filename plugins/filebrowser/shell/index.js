// Native file transfers belong to the File Browser plugin, through the existing shell-module
// interface. No preload extension, shell command, or filesystem access in the renderer.
import { app, dialog } from 'electron';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const CHUNK_BYTES = 256 * 1024;
const PREFIX = 'filebrowser-native';
const METHODS = ['start', 'status', 'cancel'].map((name) => `${PREFIX}.${name}`);
const fail = (code, message) => Object.assign(new Error(message), { code });
const fingerprint = (stat) => `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;

async function existing(file) {
  try { return await fs.lstat(file, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

export async function load(api) {
  const jobs = new Map();
  let stopping = false;
  let served;

  function update(job, values) {
    Object.assign(job.snapshot, values);
    job.snapshot.revision++;
    job.updated = Date.now();
    served.publish(`${PREFIX}.progress`, { ...job.snapshot });
  }

  function check(job) {
    if (stopping || job.controller.signal.aborted) throw fail('cancelled', 'Transfer cancelled.');
  }

  function bounded(job, operation) {
    check(job);
    return new Promise((resolve, reject) => {
      const finish = (callback, value) => {
        clearTimeout(timer);
        job.controller.signal.removeEventListener('abort', cancelled);
        callback(value);
      };
      const cancelled = () => finish(reject, fail('cancelled', 'Transfer cancelled.'));
      const timer = setTimeout(() => finish(reject, fail('unavailable', 'The local frame did not answer. Try the transfer again.')), 15_000);
      job.controller.signal.addEventListener('abort', cancelled, { once: true });
      Promise.resolve().then(operation).then((value) => finish(resolve, value), (error) => finish(reject, error));
    });
  }

  async function remote(job, local) {
    check(job);
    const peers = await bounded(job, () => local.call('mesh.peers', {}));
    const peer = peers?.peers?.find((entry) => entry.member?.node === job.snapshot.node);
    if (!peer || peer.member.local || peer.card?.software !== 'cortexterm') {
      throw fail('invalid_params', 'Choose a remote CortexTerm mesh machine.');
    }
    if (!peer.reachable) throw fail('unavailable', 'This mesh machine is offline. Reconnect it and try again.');
    const link = await bounded(job, () => local.call('mesh.link', { node: job.snapshot.node }));
    // Only the frame supplies this authenticated local tunnel. Never accept a URL from the UI.
    const base = new URL(link.url);
    if (base.protocol !== 'http:' || base.hostname !== '127.0.0.1' || !base.port) {
      throw fail('invalid_response', 'The mesh returned an invalid file-transfer link.');
    }
    return async (method, params, cleanup = false) => {
      if (!cleanup) check(job);
      const signal = cleanup ? AbortSignal.timeout(5000)
        : AbortSignal.any([job.controller.signal, AbortSignal.timeout(45_000)]);
      const response = await fetch(new URL('/api/rpc', base), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${link.token}` },
        body: JSON.stringify({ method, params }), signal,
      });
      if (!response.ok) throw fail('unavailable', `File transfer failed (${response.status}). Reconnect the machine and try again.`);
      const answer = await response.json();
      if (!answer.ok) throw fail(answer.error?.code ?? 'transfer_error', answer.error?.message ?? 'File transfer failed.');
      return answer.result;
    };
  }

  async function upload(job, call) {
    const chosen = await dialog.showOpenDialog(api.window, {
      title: 'Upload files to mesh machine', buttonLabel: 'Upload',
      properties: ['openFile', 'multiSelections', 'dontAddToRecent'],
    });
    check(job);
    if (chosen.canceled || !chosen.filePaths.length) throw fail('cancelled', 'Transfer cancelled.');
    let completed = 0;
    for (const source of chosen.filePaths) {
      check(job);
      const input = await fs.open(source, constants.O_RDONLY | constants.O_NONBLOCK);
      let transfer;
      try {
        const original = await input.stat({ bigint: true });
        if (!original.isFile() || original.size > BigInt(Number.MAX_SAFE_INTEGER)) {
          throw fail('invalid_params', `${path.basename(source)} is not a supported regular file.`);
        }
        const total = Number(original.size);
        update(job, { state: 'running', name: path.basename(source), completed, files: chosen.filePaths.length, bytes: 0, total });
        transfer = await call('filebrowser.upload.start', { directory: job.directory, name: path.basename(source), bytes: total });
        const buffer = Buffer.alloc(CHUNK_BYTES);
        let offset = 0;
        while (offset < total) {
          check(job);
          const { bytesRead } = await input.read(buffer, 0, Math.min(buffer.length, total - offset), offset);
          if (!bytesRead || fingerprint(await input.stat({ bigint: true })) !== fingerprint(original)) {
            throw fail('conflict', `${path.basename(source)} changed during upload. Upload it again.`);
          }
          const written = await call('filebrowser.upload.write', { id: transfer.id, offset, data: buffer.subarray(0, bytesRead).toString('base64') });
          offset += bytesRead;
          if (written.bytes !== offset) throw fail('invalid_response', 'The remote machine acknowledged the wrong upload offset.');
          update(job, { bytes: offset });
        }
        check(job);
        if (fingerprint(await input.stat({ bigint: true })) !== fingerprint(original)) {
          throw fail('conflict', `${path.basename(source)} changed during upload. Upload it again.`);
        }
        await call('filebrowser.upload.finish', { id: transfer.id });
        transfer = null;
        completed++;
        update(job, { completed });
      } finally {
        await input.close();
        if (transfer) await call('filebrowser.upload.cancel', { id: transfer.id }, true).catch(() => {});
      }
    }
    return { completed };
  }

  async function download(job, call) {
    const name = path.posix.basename(job.path);
    const chosen = await dialog.showSaveDialog(api.window, {
      title: 'Download file from mesh machine', buttonLabel: 'Download',
      defaultPath: path.join(app.getPath('downloads'), name),
      properties: ['showOverwriteConfirmation', 'dontAddToRecent'],
    });
    check(job);
    if (chosen.canceled || !chosen.filePath) throw fail('cancelled', 'Transfer cancelled.');
    const target = chosen.filePath;
    const before = await existing(target);
    if (before && !before.isFile()) throw fail('conflict', 'Choose a regular file destination, not a folder or symbolic link.');
    const temporary = path.join(path.dirname(target), `.cortex-download-${randomUUID()}`);
    let output;
    try {
      output = await fs.open(temporary, 'wx', 0o600);
      let offset = 0, stamp;
      update(job, { state: 'running', name, files: 1, completed: 0, bytes: 0, total: 0 });
      while (true) {
        const chunk = await call('filebrowser.read', { path: job.path, offset, stamp });
        const data = Buffer.from(chunk.data, 'base64');
        if (chunk.offset !== offset || data.length > CHUNK_BYTES || !Number.isSafeInteger(chunk.bytes) || chunk.bytes < offset + data.length
          || (!chunk.eof && !data.length) || (stamp && stamp !== chunk.stamp)) {
          throw fail('invalid_response', 'The remote machine sent an invalid download chunk.');
        }
        stamp = chunk.stamp;
        let written = 0;
        while (written < data.length) {
          check(job);
          const next = await output.write(data, written, data.length - written);
          if (!next.bytesWritten) throw fail('filesystem_error', 'The local disk stopped accepting this download.');
          written += next.bytesWritten;
        }
        offset += data.length;
        update(job, { bytes: offset, total: chunk.bytes });
        if (chunk.eof) {
          if (offset !== chunk.bytes) throw fail('invalid_response', 'The remote file ended before the download was complete.');
          break;
        }
      }
      check(job);
      await output.sync();
      await output.close();
      output = null;
      check(job);
      // The native Save dialog confirms replacement. Refuse a destination changed afterwards.
      const after = await existing(target);
      if (before) {
        if (!after || fingerprint(before) !== fingerprint(after)) throw fail('conflict', 'The destination changed during download. Choose a new destination.');
        await fs.rename(temporary, target);
      } else {
        // Unlike rename, link never silently replaces a file created during the transfer.
        await fs.link(temporary, target);
      }
      return { completed: 1, saved: target };
    } finally {
      await output?.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
    }
  }

  async function run(job) {
    // One frame client per transfer: cancelling a stalled setup closes its pending calls too.
    const local = api.connect();
    try {
      let off;
      try {
        await bounded(job, () => new Promise((resolve) => {
          if (local.connected) resolve();
          else off = local.onOpen(resolve);
        }));
      } finally { off?.(); }
      const call = await remote(job, local);
      check(job);
      const result = job.snapshot.direction === 'upload' ? await upload(job, call) : await download(job, call);
      update(job, { ...result, state: 'done' });
    } catch (error) {
      const cancelled = job.controller.signal.aborted || stopping || error.code === 'cancelled';
      update(job, { state: cancelled ? 'cancelled' : 'error', error: cancelled ? '' : error.message ?? String(error) });
    } finally { local.close(); }
  }

  served = api.serve({
    plugin_id: 'filebrowser.shell-module', version: '0.1.0', category: PREFIX, contract: `${PREFIX}@1`,
    provides: METHODS, subscribes: [], commands: [],
  }, async (method, params) => {
    if (method === `${PREFIX}.start`) {
      if (stopping) throw fail('unavailable', 'File Browser is stopping.');
      if (typeof params.id !== 'string' || !/^[a-f0-9-]{36}$/.test(params.id) || typeof params.node !== 'string' || !params.node
        || !['upload', 'download'].includes(params.direction)
        || (params.direction === 'upload' && typeof params.directory !== 'string')
        || (params.direction === 'download' && (typeof params.path !== 'string' || !params.path.startsWith('/')))) {
        throw fail('invalid_params', 'File transfer needs an ID, a remote machine, and a destination.');
      }
      if (jobs.has(params.id)) return { ...jobs.get(params.id).snapshot };
      if ([...jobs.values()].some((job) => ['choosing', 'running'].includes(job.snapshot.state))) {
        throw fail('busy', 'A file transfer is already active. Finish or cancel it first.');
      }
      for (const [id, job] of jobs) if (Date.now() - job.updated > 30 * 60_000 || jobs.size >= 50) jobs.delete(id);
      const job = {
        directory: params.directory, path: params.path, controller: new AbortController(), updated: Date.now(),
        snapshot: { id: params.id, node: params.node, direction: params.direction, directory: params.directory ?? '', revision: 0,
          state: 'choosing', name: '', completed: 0, files: 0, bytes: 0, total: 0, error: '', saved: '' },
      };
      jobs.set(params.id, job);
      // Returning first lets the caller subscribe/poll while the native dialog is open.
      job.promise = Promise.resolve().then(() => run(job));
      return { ...job.snapshot };
    }
    if (method === `${PREFIX}.status`) {
      const job = jobs.get(params.id);
      if (!job) throw fail('not_found', 'This file transfer is no longer available.');
      return { ...job.snapshot };
    }
    if (method === `${PREFIX}.cancel`) {
      jobs.get(params.id)?.controller.abort();
      return {};
    }
    throw fail('unknown_method', `Unknown File Browser method: ${method}`);
  });

  return {
    async unload() {
      stopping = true;
      for (const job of jobs.values()) job.controller.abort();
      // An OS picker can remain open until the user dismisses it. Such jobs have not opened
      // files; the cancelled check after their dialog prevents work after this module unloads.
      await Promise.allSettled([...jobs.values()].filter((job) => job.snapshot.state === 'running').map((job) => job.promise));
      served.stop();
      jobs.clear();
    },
  };
}
