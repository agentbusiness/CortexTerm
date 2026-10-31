Inspect, compress or extract tar, zip and compressed files to the intended location.

## Inspect

Identify the format with `file '<archive>'`. List entries before extraction: `tar -tf '<archive>'` or `unzip -l '<archive>'`, with a bounded display. Check the installed tool's options. The extension alone does not establish the contents.

Inspect top-level names, absolute paths, `..` components and symlinks. Do not extract an untrusted archive over a live application, home folder or configuration directory. Estimate destination space; compressed size can be much smaller than extracted size.

## Propose

Give a user-run extraction into a new named folder. For creation, state which root is archived and which paths are excluded. Do not place the output archive inside the input tree unless the tool explicitly excludes it. Quote paths with spaces.

## Verify

List the extracted folder and check the expected files. Preserve the original archive until the result is checked. If extraction fails halfway, report the exact error and partial destination; do not remove it or retry over it blindly. Archives containing credentials need protected storage and deliberate sharing.
