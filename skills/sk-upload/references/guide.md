# File upload guide

Source: OWASP File Upload Cheat Sheet. Storage- and language-neutral. An upload has four stages; each has its own
controls: **accept** (who, what, how big), **store** (where, under what name, with what permissions), **process**
(parsers, converters, archives) and **serve** (to whom, with what headers, from which origin).

## Accept (UPL-TYPE, UPL-SIZE, UPL-AUTH)

- Authenticated, rate-limited, CSRF-protected (unless anonymous upload is a feature).
- Allow-list extensions for the use case (e.g. `.png .jpg .jpeg .webp .pdf`), checked after decoding and
  normalizing the name (no double extensions like `x.php.jpg`, no trailing dots/spaces, no null bytes).
- Verify content: magic-byte detection (`file-type`, `python-magic`, `http.DetectContentType`, Tika) and, for images,
  decode and re-encode. Never trust the client `Content-Type`.
- Limits: per file, per request, per user/day; pixel limits for images; total uncompressed size and entry count for
  archives.

## Store (UPL-NAME, UPL-STORE, UPL-ACL, UPL-PRESIGN)

- Name files with a server-generated ID (UUID); keep the original name only as metadata (sanitized) for display.
- Store outside the web root and code directories, ideally in object storage with private ACLs.
- Presigned uploads: fixed key prefix per user, exact content type, `content-length-range`, short expiry.

## Process (UPL-PROC, UPL-ARCHIVE, UPL-XML, UPL-MALWARE)

- Keep processors patched; harden ImageMagick (`policy.xml`: disable MSL, MVG, PS, EPS, PDF, XPS, URL, TEXT coders),
  limit resources/timeouts, run converters (Ghostscript, LibreOffice, ffmpeg, wkhtmltopdf) in isolated
  containers without network access.
- Archives: for each entry, resolve the destination and require it to stay inside the target directory (zip slip);
  reject symlinks and absolute paths; cap size and count. Python: `tar.extractall(filter='data')`.
- XML-based formats (SVG, DOCX, XLSX, ODT): parse with external entities disabled.
- Files shared with other users: antivirus scanning or content disarm & reconstruction.

## Serve (UPL-SERVE, UPL-ACL)

- Check authorization on every download (the file belongs to/was shared with the caller).
- `Content-Type` from your stored, verified type; `X-Content-Type-Options: nosniff`;
  `Content-Disposition: attachment; filename*=UTF-8''…` for anything not meant to render.
- Serve user content from a separate, cookie-less domain (e.g. `usercontent.example`) so uploaded HTML/SVG cannot run
  script on your app origin. Short-lived signed URLs for private objects.
