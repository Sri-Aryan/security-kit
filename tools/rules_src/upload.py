"""sk-upload rules."""

SKILL = "sk-upload"

MACROS = {
    "UPLOAD": r"multer\(|\.single\(|\.array\(|\.fields\(|UploadFile|request\.files|req\.files?\b|MultipartFile|IFormFile|\$_FILES|formidable|busboy|FileField|ImageField|@UploadedFile|ctx\.request\.files|c\.FormFile\(|r\.FormFile\(|ParseMultipartForm|fastify-multipart|request\.FILES",
    "ORIG_NAME": r"originalname|original_filename|originalFilename|getOriginalFilename\(\)|\.filename\b|FileName\b|file\.name\b|\$_FILES\[[^\]]+\]\[['\"]name['\"]\]|Header\.Filename",
}

RULES = [
    {
        "id": "upl-mimetype-only", "check_id": "UPL-TYPE-001", "title": "Upload type checked only via the client-supplied Content-Type",
        "files": ["code"], "pattern": r"\.(mimetype|content_type|contentType|ContentType|getContentType\(\)|type)\b\s*(===?|!==?|==|!=|\.startsWith|\.startswith|in\b|\.includes)",
        "near": {"pattern": "{{UPLOAD}}|(?i:upload|file)", "lines": 6},
        "not_near": {"pattern": r"(?i)(file-type|fileTypeFromBuffer|magic|python-magic|filetype\.guess|imghdr|DetectContentType|Tika|mmmagic|mime\.lookup|libmagic|signature)", "lines": 10},
        "confidence": "MEDIUM", "note": "Content-Type is set by the client; verify extension allow-list and file signature.",
        "examples": {"match": ["if (req.file.mimetype !== 'image/png') return res.sendStatus(400);"], "no_match": ["const t = await fileTypeFromBuffer(buf);\nif (t?.mime !== 'image/png' || req.file.mimetype !== 'image/png') return res.sendStatus(400);"]},
    },
    {
        "id": "upl-no-type-check", "check_id": "UPL-TYPE-001", "type": "absence", "scope": "file",
        "title": "Upload handler with no file type validation", "files": ["code"], "when": "{{UPLOAD}}",
        "missing": r"(?i)(fileFilter|allowed_?(ext|types|mime)|ALLOWED_|accept\s*:|mimetype|content_type|extname|splitext|getExtension|file-type|magic|filetype|FileExtensionValidator|validate_image|isImage|image/)",
        "confidence": "MEDIUM",
        "examples": {"match": ["const upload = multer({ dest: 'uploads/' });\nrouter.post('/avatar', upload.single('file'), save);"], "no_match": ["const upload = multer({ dest: 'tmp/', fileFilter: imagesOnly });"]},
    },
    {
        "id": "upl-original-name-path", "check_id": "UPL-NAME-001", "title": "Client filename used to build the storage path", "files": ["code"],
        "pattern": r"(path\.join|path\.resolve|os\.path\.join|filepath\.Join|Paths\.get|new\s+File|join|\+\s*['\"`]?/?)\s*\(?[^)\n]*({{ORIG_NAME}})",
        "not_near": {"pattern": r"(?i)(secure_filename|basename|sanitize|uuid|randomUUID|randomBytes|nanoid|token_hex|uuid4|Guid\.NewGuid|slugify)", "lines": 2},
        "confidence": "HIGH",
        "examples": {"match": ["const dest = path.join(UPLOAD_DIR, req.file.originalname);", "f.save(os.path.join(UPLOAD_FOLDER, f.filename))"],
                     "no_match": ["const dest = path.join(UPLOAD_DIR, `${crypto.randomUUID()}.png`);", "f.save(os.path.join(UPLOAD_FOLDER, secure_filename(f.filename)))"]},
    },
    {
        "id": "upl-multer-keep-name", "check_id": "UPL-NAME-001", "title": "Storage engine keeps the original filename", "files": ["js"],
        "pattern": r"filename\s*[:(]\s*[^\n]*\bcb\(\s*null\s*,\s*[^)]*originalname", "confidence": "HIGH",
        "examples": {"match": ["filename: (req, file, cb) => cb(null, file.originalname)"], "no_match": ["filename: (req, file, cb) => cb(null, crypto.randomUUID() + ext)"]},
    },
    {
        "id": "upl-no-size-limit", "check_id": "UPL-SIZE-001", "type": "absence", "scope": "file",
        "title": "Upload handler with no size limit", "files": ["code", "config"], "when": "{{UPLOAD}}",
        "missing": r"(?i)(limits\s*:|fileSize|maxFileSize|max_?file_?size|MAX_CONTENT_LENGTH|max-file-size|max-request-size|MaxBytesReader|ParseMultipartForm\(\s*\d|DATA_UPLOAD_MAX|FILE_UPLOAD_MAX|RequestSizeLimit|MultipartBodyLengthLimit|bodyLimit|client_max_body_size|maxBodyLength)",
        "confidence": "MEDIUM",
        "examples": {"match": ["const upload = multer({ dest: 'tmp/' });\napp.post('/u', upload.single('f'), h);"], "no_match": ["const upload = multer({ dest: 'tmp/', limits: { fileSize: 5 * 1024 * 1024 } });"]},
    },
    {
        "id": "upl-pillow-bomb", "check_id": "UPL-SIZE-001", "title": "Image decompression-bomb protection disabled", "files": ["py", "code"],
        "pattern": r"MAX_IMAGE_PIXELS\s*=\s*None|limitInputPixels\s*:\s*false|ImageFile\.LOAD_TRUNCATED_IMAGES\s*=\s*True", "confidence": "MEDIUM",
        "examples": {"match": ["Image.MAX_IMAGE_PIXELS = None"], "no_match": ["Image.MAX_IMAGE_PIXELS = 50_000_000"]},
    },
    {
        "id": "upl-stored-in-webroot", "check_id": "UPL-STORE-001", "title": "Uploads stored inside a public/web-served directory", "files": ["code", "config"],
        "pattern": r"(?i)(dest|destination|upload_?(folder|dir|path)|UPLOAD_\w*|MEDIA_ROOT|storage_path|path)\s*[:=]\s*[^\n]*['\"`]\.?/?(public|static|www|wwwroot|htdocs|html|web)/",
        "confidence": "HIGH", "note": "In PHP/ASP/JSP-capable servers an uploaded script in the web root can execute; elsewhere it is served inline.",
        "examples": {"match": ["const upload = multer({ dest: 'public/uploads/' });", "UPLOAD_FOLDER = './static/uploads'"], "no_match": ["const upload = multer({ dest: '/var/app-data/uploads/' });"]},
    },
    {
        "id": "upl-served-inline", "check_id": "UPL-SERVE-001", "title": "Uploaded files served statically from the app origin", "files": ["code", "config"],
        "pattern": r"(?i)express\.static\(\s*['\"`][^'\"`]*uploads?|app\.use\(\s*['\"]/(uploads?|files|media|attachments)['\"]\s*,\s*express\.static|location\s+/(uploads?|media|files)\b|STATIC_URL[^\n]*uploads|send_from_directory\(\s*[^,]*UPLOAD",
        "confidence": "MEDIUM", "note": "Serve with Content-Disposition: attachment + nosniff, or from a separate sandbox domain.",
        "examples": {"match": ["app.use('/uploads', express.static('uploads'));"], "no_match": ["app.get('/files/:id', authz, (req, res) => res.download(pathFor(req.params.id)));"]},
    },
    {
        "id": "upl-public-acl", "check_id": "UPL-ACL-001", "title": "Uploaded objects stored with a public ACL", "files": ["code", "config", "tf"],
        "pattern": r"(?i)ACL\s*[:=]\s*['\"]public-read(-write)?['\"]|acl\s*=\s*['\"]public-read|block_public_acls\s*=\s*false|PublicAccessBlockConfiguration[\s\S]{0,80}false|allUsers|predefinedAcl\s*:\s*['\"]publicRead|makePublic\(\)",
        "confidence": "HIGH",
        "examples": {"match": ["await s3.send(new PutObjectCommand({ Bucket, Key, Body, ACL: 'public-read' }));"], "no_match": ["await s3.send(new PutObjectCommand({ Bucket, Key, Body }));"]},
    },
    {
        "id": "upl-long-signed-url", "check_id": "UPL-ACL-001", "title": "Long-lived signed URL", "files": ["code"],
        "pattern": r"(?i)(expiresIn|Expires|expiration|expires_in|ExpiresIn)\s*[:=]\s*(\d{6,}|[1-9]\d{4,5}\b|60\s*\*\s*60\s*\*\s*(2[4-9]|[3-9]\d|\d{3,})|7\s*\*\s*24)",
        "near": {"pattern": r"(?i)(getSignedUrl|presign|generate_presigned_url|signedUrl|getSignedUrlPromise|createSignedUrl|SAS|generateSignedUrl)", "lines": 4},
        "confidence": "LOW",
        "examples": {"match": ["const url = await getSignedUrl(s3, cmd, { expiresIn: 604800 });"], "no_match": ["const url = await getSignedUrl(s3, cmd, { expiresIn: 300 });"]},
    },
    {
        "id": "upl-presign-unconstrained", "check_id": "UPL-PRESIGN-001", "title": "Presigned upload without content-type/size constraints", "files": ["code"],
        "pattern": r"createPresignedPost\(|generate_presigned_post\(|getSignedUrl\([^)]*PutObjectCommand|generate_presigned_url\(\s*['\"]put_object['\"]",
        "not_near": {"pattern": r"(content-length-range|ContentLength|Conditions|ContentType\s*:|content_type|Fields\s*[:=])", "lines": 6},
        "confidence": "MEDIUM", "note": "Fix the key prefix, content type and size range in the policy.",
        "examples": {"match": ["const { url, fields } = await createPresignedPost(s3, { Bucket, Key: req.body.key });"], "no_match": ["await createPresignedPost(s3, { Bucket, Key: `u/${uid}/${id}`, Conditions: [['content-length-range', 0, 5e6]], Fields: { 'Content-Type': 'image/png' } });"]},
    },
    {
        "id": "upl-imagemagick", "check_id": "UPL-PROC-001", "title": "User files processed with ImageMagick/Ghostscript/LibreOffice/ffmpeg", "files": ["code", "docker"],
        "pattern": r"(?i)\b(imagemagick|gm\(|graphicsmagick|convert\s+[^\n]*\$|magick\s|Wand\(|wand\.image|gs\s+-|ghostscript|soffice|libreoffice|unoconv|ffmpeg|exiftool|pdftk|wkhtmltopdf)\b",
        "confidence": "LOW", "note": "Confirm patched versions, a restrictive ImageMagick policy.xml (disable MSL/MVG/PS/EPS/PDF/URL coders), timeouts and isolation.",
        "examples": {"match": ["execFile('convert', [input, '-resize', '200x200', out])  // imagemagick"], "no_match": ["const out = await sharp(input).resize(200).toBuffer();"]},
    },
    {
        "id": "upl-zip-slip", "check_id": "UPL-ARCHIVE-001", "title": "Archive extracted without path checks (zip slip)", "files": ["code"],
        "pattern": r"\.extractall\(|ZipFile\([^)]*\)\.extract\(|tarfile\.open\([^)]*\)\.extractall|adm-zip|extractAllTo\(|unzipper\.Extract|\.pipe\(\s*unzip|decompress\(|ZipInputStream|ZipArchive\b|ExtractToDirectory\(|archive/zip|zip\.OpenReader",
        "not_near": {"pattern": r"(?i)(filter\s*=\s*['\"]data|is_within_directory|commonpath|startsWith\(|startswith\(|getCanonicalPath|normalize\(|HasPrefix|realpath|\.\.)", "lines": 8},
        "confidence": "MEDIUM", "note": "Validate each entry's resolved path stays inside the target directory; reject symlinks; cap total size and file count.",
        "examples": {"match": ["with zipfile.ZipFile(f) as z:\n    z.extractall(dest)"], "no_match": ["tar.extractall(dest, filter='data')"]},
    },
    {
        "id": "upl-xml-parse", "check_id": "UPL-XML-001", "title": "Uploaded XML/SVG/Office file parsed with an XML parser", "files": ["code"],
        "pattern": r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.new\w*\(|etree\.(parse|fromstring)\(|xml2js|libxmljs\.parseXml|DOMParser|XmlDocument\(|simplexml_load_(string|file)|openpyxl\.load_workbook|python-docx|Nokogiri::XML",
        "near": {"pattern": "{{UPLOAD}}|(?i:upload|svg|docx|xlsx|import)", "lines": 6},
        "not_near": {"pattern": r"(?i)(defusedxml|disallow-doctype-decl|resolve_entities\s*=\s*False|FEATURE_SECURE_PROCESSING|DtdProcessing\.Prohibit|noent\s*:\s*false|nonet)", "lines": 8},
        "confidence": "MEDIUM",
        "examples": {"match": ["svg = etree.fromstring(request.files['logo'].read())"], "no_match": ["svg = defusedxml.ElementTree.fromstring(request.files['logo'].read())"]},
    },
    {
        "id": "upl-no-malware-scan", "check_id": "UPL-MALWARE-001", "type": "absence", "scope": "project",
        "title": "User files shared with others but no malware scanning", "files": ["code", "config", "docker"],
        "when": r"(?i)(attachment|shared_?file|document|upload)\w*", "file_requires": "{{UPLOAD}}",
        "missing": r"(?i)(clamav|clamd|clamscan|virustotal|malware|antivirus|scan_?file|GuardDuty|Defender|cdr|dangerzone|opswat)",
        "confidence": "LOW",
        "examples": {"match": ["router.post('/documents', upload.single('file'), saveDocument)"], "no_match": ["router.post('/documents', upload.single('file'), clamscan, saveDocument)"]},
    },
    {
        "id": "upl-unauthenticated", "check_id": "UPL-AUTH-001", "title": "Upload route registered without middleware", "files": ["js"],
        "pattern": r"\b(app|router)\.(post|put)\(\s*['\"`][^'\"`]*['\"`]\s*,\s*(upload|multer\w*|\w*[uU]pload\w*)\.(single|array|fields|any)\(",
        "confidence": "LOW", "note": "Confirm authentication is applied at the router level.",
        "examples": {"match": ["router.post('/avatar', upload.single('file'), save)"], "no_match": ["router.post('/avatar', requireAuth, upload.single('file'), save)"]},
    },
]
