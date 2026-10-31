#!/usr/bin/env python3
"""Inspect or preview a config; apply only through the person's explicit command."""
import argparse
import csv
import ctypes
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import stat
import sys
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET

MAX_FILE = 256 * 1024
MAX_REQUEST = 320 * 1024
MAX_EDIT = 16 * 1024
MAX_LINES = 60
MAX_OUTPUT = 4000
FORMATS = {"text", "json", "jsonc", "jsonl", "toml", "yaml", "xml", "plist", "ini", "env", "shell", "nginx", "haproxy", "systemd", "ssh", "hcl", "csv", "tsv", "sql"}
SENSITIVE = re.compile(r"(?i)(password|passwd|secret|credential|(?:api|private|access)[_-]?key|authorization|(?:auth|access|refresh|session|security|bearer)[_-]?token|(?<![a-z0-9])token(?![_-](?:limit|count|budget|length|size)\b)(?![a-z0-9]))")
URI_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/@:]+:)[^\s/@]+(@)", re.I)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def fail(message):
    raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_path(value):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 or ord(c) == 127 or unicodedata.category(c) == "Cf" for c in value):
        fail("Give one file path without control characters.")
    return Path(value).expanduser()


def within(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def location(value, cwd, home):
    given = clean_path(value)
    if not given.is_absolute():
        if not cwd:
            fail("A relative path needs the terminal's folder.")
        given = clean_path(cwd) / given
    given = Path(os.path.abspath(given))
    target = given.resolve(strict=True)
    if home and within(target, clean_path(home).resolve()):
        fail("Use the app's settings for CortexTerm control files.")
    return given, target


def load_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        meta = os.fstat(handle.fileno())
        if not stat.S_ISREG(meta.st_mode):
            fail("Only regular text files are supported.")
        if meta.st_size > MAX_FILE:
            fail("This file exceeds 256 KiB; use the editor and select a smaller section.")
        data = handle.read(MAX_FILE + 1)
        after = os.fstat(handle.fileno())
        if (meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            fail("The file changed while reading; inspect it again.")
        if len(data) > MAX_FILE:
            fail("The file grew beyond 256 KiB while reading.")
    text = data.decode("utf-8")
    if "\x00" in text:
        fail("This is not a UTF-8 text configuration.")
    if re.search(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", text):
        fail("Private-key files are not shown or edited by this helper.")
    return data, text, meta


def kind(path, requested):
    name = path.name.lower()
    suffix = path.suffix.lower()
    inferred = "env" if name == ".env" or name.startswith(".env.") else {".json": "json", ".jsonc": "jsonc", ".jsonl": "jsonl", ".ndjson": "jsonl", ".toml": "toml", ".yaml": "yaml", ".yml": "yaml", ".xml": "xml", ".plist": "plist", ".ini": "ini", ".csv": "csv", ".tsv": "tsv", ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".sql": "sql", ".tf": "hcl"}.get(suffix, "text")
    if requested:
        if requested not in FORMATS:
            fail("Unsupported format; choose a listed format.")
        # A caller cannot evade or widen a filename's known parser. JSONC-in-.json
        # product dialects use the native editor and that product's validator.
        compatible = inferred == requested
        if inferred != "text" and not compatible:
            fail("The filename identifies " + inferred + "; do not downgrade or change its parser. Use the native editor for another dialect.")
        return requested
    return inferred


def redact(text, fmt="text"):
    # XML attributes may be ordered or split across lines: a value can appear
    # before its secret-bearing name. Do not stream part of such a document.
    xml_like = fmt in {"xml", "plist"} or bool(re.search(r"<[/!?A-Za-z_][^>]*", text))
    if xml_like and SENSITIVE.search(text):
        return "\n".join("[REDACTED XML with secret-like fields]" for _ in text.splitlines()) + ("\n" if text.endswith("\n") else "")
    output = []
    hide_rest = False
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line.rstrip("\r\n")
        stripped = body.lstrip(" +-\t")
        if hide_rest:
            body = "[REDACTED after multiline secret]"
        elif fmt == "env" and re.match(r"(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
            # Dotenv keys do not reliably identify which values are credentials.
            body = re.sub(r"(=).*", r"\1[REDACTED]", body)
            trailing_slashes = len(stripped) - len(stripped.rstrip("\\"))
            hide_rest = stripped.count('"') % 2 == 1 or stripped.count("'") % 2 == 1 or trailing_slashes % 2 == 1
        elif SENSITIVE.search(body):
            # Do not leak continuations, nested secret mappings or XML text. A
            # conservative cutoff is preferable to guessing their full dialect.
            hide_rest = stripped.rstrip().endswith((":", "=", "{", "[", "|", ">")) or stripped.count('"') % 2 == 1 or stripped.count("'") % 2 == 1
            body = "[REDACTED sensitive line]"
        body = URI_PASSWORD.sub(r"\1[REDACTED]\2", body)
        body = JWT.sub("[REDACTED token]", body)
        output.append(body + newline)
    return "".join(output)


def strict_json(text):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                fail("Duplicate JSON key: " + key)
            out[key] = value
        return out
    def constant(value):
        fail("Not a JSON number: " + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def jsonc_text(text):
    # Remove comments outside strings, retaining line boundaries for error locations.
    out, pos, quoted, escaped = [], 0, False, False
    while pos < len(text):
        c = text[pos]
        if quoted:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
            pos += 1
        elif c == '"':
            quoted = True
            out.append(c)
            pos += 1
        elif text.startswith("//", pos):
            end = text.find("\n", pos)
            if end < 0:
                end = len(text)
            out.extend(" " * (end - pos))
            pos = end
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            if end < 0:
                fail("Unclosed JSONC comment.")
            out.extend("\n" if x == "\n" else " " for x in text[pos:end + 2])
            pos = end + 2
        else:
            out.append(c)
            pos += 1
    # JSONC accepts comments and trailing commas, not JSON5 expressions or bare keys.
    value = "".join(out)
    out, quoted, escaped = [], False, False
    for pos, c in enumerate(value):
        if quoted:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
            out.append(c)
        elif c == "," and value[pos + 1:].lstrip().startswith(("}", "]")):
            out.append(" ")
        else:
            out.append(c)
    return "".join(out)


def validate(text, fmt):
    try:
        if fmt == "json":
            strict_json(text)
        elif fmt == "jsonc":
            strict_json(jsonc_text(text))
        elif fmt == "jsonl":
            # JSON Lines uses LF record boundaries. A final LF is a terminator,
            # not an extra blank record; embedded Unicode separators remain data.
            records = text.split("\n") if text else []
            if text.endswith("\n"):
                records.pop()
            for number, record in enumerate(records, 1):
                if not record.strip():
                    return {"status": "invalid", "detail": "Blank JSONL record at line " + str(number) + ". No proposal was created."}
                try:
                    strict_json(record)
                except Exception as error:
                    column = getattr(error, "colno", None)
                    detail = type(error).__name__ + " at line " + str(number) + (", column " + str(column) if column else "")
                    return {"status": "invalid", "detail": detail + ". Parser text is omitted to protect values."}
        elif fmt == "toml":
            try:
                import tomllib
            except ImportError:
                try:
                    import tomli as tomllib
                except ImportError:
                    return {"status": "unavailable", "detail": "TOML parsing needs Python 3.11+ or an already installed tomli."}
            tomllib.loads(text)
        elif fmt == "yaml":
            try:
                import yaml
            except ImportError:
                return {"status": "unavailable", "detail": "YAML parsing needs an already installed PyYAML. Use the product's validator or editor."}
            class UniqueLoader(yaml.SafeLoader):
                pass
            def mapping(loader, node, deep=False):
                result = {}
                for key_node, value_node in node.value:
                    key = loader.construct_object(key_node, deep=deep)
                    if key in result:
                        fail("Duplicate YAML key.")
                    result[key] = loader.construct_object(value_node, deep=deep)
                return result
            UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
            list(yaml.load_all(text, Loader=UniqueLoader))
        elif fmt in {"xml", "plist"}:
            if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, re.I):
                # Apple's standard plist DOCTYPE has no internal subset or entity expansion.
                if fmt != "plist" or re.search(r"<!\s*ENTITY\b|<!\s*DOCTYPE[^>]*\[", text, re.I):
                    fail("DTD/entity declarations are unsupported; use a trusted product-specific validator.")
            if fmt == "plist":
                plistlib.loads(text.encode("utf-8"))
            else:
                ET.fromstring(text)
        elif fmt == "ini":
            import configparser
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(text)
        elif fmt in {"csv", "tsv"}:
            list(csv.reader(io.StringIO(text), delimiter="\t" if fmt == "tsv" else ",", strict=True))
        else:
            return {"status": "not_checked", "detail": "No generic parser for this dialect. Run the installed product's validator before reload; this helper does not execute configuration."}
        return {"status": "valid", "detail": "Format parsed. This does not verify product settings, included files or service behavior."}
    except Exception as error:
        # Parser exceptions can repeat the secret-bearing input line.
        line = getattr(error, "lineno", None)
        column = getattr(error, "colno", None)
        position = getattr(error, "position", None)
        if position is not None:
            line, column = position[0], position[1] + 1
        if line is None:
            location_match = re.search(r"at line (\d+), column (\d+)", str(error))
            if location_match:
                line, column = int(location_match[1]), int(location_match[2])
        mark = getattr(error, "problem_mark", None)
        if mark is not None:
            line, column = mark.line + 1, mark.column + 1
        detail = type(error).__name__ + (" at line " + str(line) if line else "") + (", column " + str(column) if column else "")
        return {"status": "invalid", "detail": detail + ". Open this location in the editor; parser text is omitted to protect values."}


def private_directory(home):
    app_home = clean_path(home).resolve(strict=True)
    meta = app_home.stat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) & 0o022:
        fail("CortexTerm home must be owned by you and not writable by other users.")
    folder = app_home / "config-proposals"
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError:
        pass
    meta = folder.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) & 0o077:
        fail("The config proposal folder must be a private directory owned by you.")
    return folder


def require_metadata_support(path):
    if sys.platform == "darwin":
        return  # fcopyfile preserves ACLs and extended attributes during apply.
    if not hasattr(os, "listxattr"):
        fail("Cannot inspect extended metadata; use the native editor.")
    if os.listxattr(path):
        fail("This platform's extended metadata needs the native editor.")


def preserve_metadata(source, destination_fd):
    if sys.platform != "darwin":
        return
    # Copy metadata only, never the source data over the proposed text.
    # COPYFILE_ACL = 1 and COPYFILE_XATTR = 4 in the system copyfile.h.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fcopyfile.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    libc.fcopyfile.restype = ctypes.c_int
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if libc.fcopyfile(source_fd, destination_fd, None, 5) != 0:
            fail("Cannot preserve the file's ACLs and extended attributes; nothing was replaced.")
    finally:
        os.close(source_fd)


def identity(meta):
    return {"device": meta.st_dev, "inode": meta.st_ino, "uid": meta.st_uid, "gid": meta.st_gid, "mode": stat.S_IMODE(meta.st_mode), "links": meta.st_nlink, "modified_ns": meta.st_mtime_ns, "changed_ns": meta.st_ctime_ns}


def candidate(text, old, new):
    if not isinstance(old, str) or not isinstance(new, str) or not old:
        fail("Preview needs non-empty old_text and a string new_text.")
    if max(len(old.encode()), len(new.encode())) > MAX_EDIT:
        fail("Select an edit below 16 KiB.")
    if "\r\n" in text and not re.search(r"(?<!\r)\n", text):
        old = old.replace("\r\n", "\n").replace("\n", "\r\n")
        new = new.replace("\r\n", "\n").replace("\n", "\r\n")
    if old == new:
        fail("The replacement is unchanged.")
    if "[REDACTED" in old or "[REDACTED" in new:
        fail("Redacted values cannot be replaced; use the editor for secret changes.")
    if text.count(old) != 1:
        fail("old_text must match exactly once. Inspect the current file and include unique context.")
    for changed in (old, new):
        if SENSITIVE.search(changed) or URI_PASSWORD.search(changed) or JWT.search(changed):
            fail("Use the editor for secret-bearing changes; secret values never enter proposal commands.")
    result = text.replace(old, new, 1)
    if len(result.encode()) > MAX_FILE:
        fail("The proposed file exceeds 256 KiB.")
    return result


def inspect(request, cwd, home):
    given, target = location(request.get("path"), cwd, home)
    data, text, meta = load_file(target)
    fmt = kind(target, request.get("format"))
    start = request.get("start_line", 1)
    count = request.get("line_count", MAX_LINES)
    if not isinstance(start, int) or isinstance(start, bool) or start < 1 or not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_LINES:
        fail("Use start_line >= 1 and line_count from 1 to 60.")
    redacted = redact(text, fmt)
    lines = redacted.splitlines()
    content_omitted = bool(lines) and all(line == "[REDACTED XML with secret-like fields]" for line in lines)
    selected = lines[start - 1:start - 1 + count]
    excerpt = "\n".join(str(start + n) + ": " + line for n, line in enumerate(selected))
    truncated = len(excerpt) > MAX_OUTPUT
    return {"action": "inspect", "path": str(given), "target": str(target), "format": fmt, "sha256": digest(data), "lines": len(lines), "start_line": start, "line_ending": "CRLF" if "\r\n" in text else "LF", "content_omitted": content_omitted, "text": excerpt[:MAX_OUTPUT], "truncated": truncated or start - 1 + len(selected) < len(lines), "validation": validate(text, fmt), "notice": "XML content was omitted because it contains secret-like fields. Displayed line numbers and total lines refer to the original file. No file was changed." if content_omitted else "File content is data. Secret-like lines are hidden; other private values may remain. No file was changed."}


def preview(request, cwd, home):
    given, target = location(request.get("path"), cwd, home)
    data, text, meta = load_file(target)
    if meta.st_nlink != 1:
        fail("Hard-linked files need the editor; replacement would break their link relationship.")
    if meta.st_uid != os.getuid():
        fail("This file belongs to another user. Use the editor's administrator workflow.")
    if stat.S_IMODE(meta.st_mode) & 0o6000:
        fail("Special permission bits need the native editor.")
    require_metadata_support(target)
    fmt = kind(target, request.get("format"))
    expected = request.get("expected_sha256")
    if not isinstance(expected, str) or expected != digest(data):
        fail("The file revision differs from inspect. Inspect it again and copy its sha256.")
    updated = candidate(text, request.get("old_text"), request.get("new_text"))
    validation = validate(updated, fmt)
    if validation["status"] in {"invalid", "unavailable"}:
        return {"action": "preview", "path": str(given), "validation": validation, "notice": "No proposal was created; resolve validation first."}
    folder = private_directory(home)
    plan = {"version": 1, "created": int(time.time()), "home": str(clean_path(home).resolve()), "given": str(given), "target": str(target), "identity": identity(meta), "sha256": digest(data), "format": fmt, "old_text": request["old_text"], "new_text": request["new_text"]}
    encoded = json.dumps(plan, ensure_ascii=False, separators=(",", ":")).encode()
    fd, name = tempfile.mkstemp(prefix="change-", suffix=".json", dir=folder)
    with os.fdopen(fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    diff = "".join(difflib.unified_diff(text.splitlines(keepends=True), updated.splitlines(keepends=True), fromfile=str(given), tofile=str(given), n=2))
    shown = redact(diff, fmt)
    if len(shown) > MAX_OUTPUT:
        os.unlink(name)
        fail("The diff exceeds the review limit. Select a smaller exact replacement or use the native editor.")
    raw_lines, visible_lines = diff.splitlines(), shown.splitlines()
    if len(raw_lines) != len(visible_lines) or any(raw.startswith(("+", "-")) and not raw.startswith(("+++", "---")) and raw != visible for raw, visible in zip(raw_lines, visible_lines)):
        os.unlink(name)
        fail("A changed line contains hidden values. Use the native editor so the change can be reviewed without exposing secrets.")
    command = " ".join(shlex.quote(x) for x in (sys.executable, str(Path(__file__).resolve()), "apply", name, "--digest", digest(encoded)))
    return {"action": "preview", "path": str(given), "format": fmt, "sha256": digest(data), "recovery": "Apply returns a private backup path. Review that backup in the editor before restoring; do not overwrite a newer revision.", "diff": shown[:MAX_OUTPUT], "truncated": len(shown) > MAX_OUTPUT, "validation": validation, "apply_command": command, "notice": "Preview only. Put apply_command in one sh block for the person to run. It rechecks the file, saves a private backup, and replaces only this match. It does not reload or restart the service. Proposal expires after 24 hours.", "next": "Run the product's configuration check and then verify the intended service after a user-run reload."}


def apply(plan_path, expected_digest):
    path = clean_path(plan_path)
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) & 0o077 or meta.st_size > MAX_REQUEST:
        fail("The proposal must be a private regular file owned by the current user. Do not apply it with sudo.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) & 0o077:
            fail("The opened proposal is not a private regular file owned by you.")
        encoded = handle.read(MAX_REQUEST + 1)
    if len(encoded) > MAX_REQUEST or not re.fullmatch(r"[0-9a-f]{64}", expected_digest or "") or digest(encoded) != expected_digest:
        fail("The proposal changed after preview. Create a fresh preview.")
    plan = strict_json(encoded.decode("utf-8"))
    if plan.get("version") != 1 or not isinstance(plan.get("created"), int) or not 0 <= time.time() - plan["created"] <= 86400:
        fail("The proposal is invalid or expired. Create a fresh preview.")
    folder = private_directory(plan["home"])
    if path.resolve().parent != folder:
        fail("The proposal is outside CortexTerm's private proposal folder.")
    given, target = location(plan["given"], None, plan["home"])
    if str(target) != plan["target"]:
        fail("The file's symbolic-link target changed. Inspect it again.")
    data, text, meta = load_file(target)
    if identity(meta) != plan["identity"] or digest(data) != plan["sha256"]:
        fail("The file changed after preview. Inspect it again.")
    if meta.st_uid != os.getuid() or meta.st_nlink != 1:
        fail("File ownership or link count is unsupported.")
    require_metadata_support(target)
    updated = candidate(text, plan["old_text"], plan["new_text"])
    validation = validate(updated, plan["format"])
    if validation["status"] in {"invalid", "unavailable"}:
        fail("The proposed file no longer passes format validation.")
    backup_fd, backup = tempfile.mkstemp(prefix="backup-", suffix=".txt", dir=folder)
    with os.fdopen(backup_fd, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    temp_fd, temporary = tempfile.mkstemp(prefix="." + target.name + ".cortexterm-", dir=target.parent)
    try:
        with os.fdopen(temp_fd, "wb") as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(meta.st_mode))
            os.fchown(handle.fileno(), meta.st_uid, meta.st_gid)
            handle.write(updated.encode("utf-8"))
            handle.flush()
            preserve_metadata(target, handle.fileno())
            os.fsync(handle.fileno())
        latest_data, _, latest = load_file(target)
        if identity(latest) != plan["identity"] or digest(latest_data) != plan["sha256"] or given.resolve(strict=True) != target:
            fail("The file changed during apply. Nothing was replaced.")
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    path.unlink()
    return {"action": "apply", "path": str(given), "backup": backup, "sha256": digest(updated.encode("utf-8")), "validation": validation, "notice": "File saved. The service has not been reloaded or verified. To recover, review the private backup in the editor and restore it only if the current file is still this revision."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "preview", "apply"))
    parser.add_argument("plan", nargs="?")
    parser.add_argument("--digest")
    parser.add_argument("--cwd")
    parser.add_argument("--home")
    args = parser.parse_args()
    try:
        if args.action == "apply":
            if args.cwd or args.home:
                fail("Apply uses only its reviewed plan and digest.")
            result = apply(args.plan, args.digest)
        else:
            if args.plan or args.digest:
                fail("Inspect/preview do not accept an apply plan or digest.")
            if not args.home:
                fail("CortexTerm home is required.")
            raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
            if len(raw) > MAX_REQUEST:
                fail("Configuration request exceeds 320 KiB.")
            request = strict_json(raw.decode("utf-8"))
            if not isinstance(request, dict):
                fail("Configuration request must be an object.")
            allowed = {"action", "path", "format", "start_line", "line_count", "expected_sha256", "old_text", "new_text"}
            if set(request) - allowed:
                fail("Unknown configuration request fields.")
            if "action" in request and request["action"] != args.action:
                fail("The request action differs from the selected helper action.")
            if args.action == "inspect" and any(key in request for key in ("expected_sha256", "old_text", "new_text")):
                fail("Inspect does not accept replacement fields.")
            if args.action == "preview" and any(key in request for key in ("start_line", "line_count")):
                fail("Preview needs exact replacement text, not display line ranges.")
            result = inspect(request, args.cwd, args.home) if args.action == "inspect" else preview(request, args.cwd, args.home)
        print(json.dumps(result, ensure_ascii=False))
    except Exception as error:
        # Filesystem exceptions expose paths, but never input file lines or request values.
        message = str(error) if isinstance(error, (ValueError, OSError)) and not isinstance(error, UnicodeError) else type(error).__name__
        print(json.dumps({"error": message, "notice": "No service was reloaded. Inspect current file state before retrying."}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
