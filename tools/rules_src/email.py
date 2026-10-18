"""sk-email rules."""

SKILL = "sk-email"

MACROS = {
    "MAIL_CALL": r"(?i:sendMail|send_mail|send_mass_mail|transporter|nodemailer|smtplib|EmailMessage|EmailMultiAlternatives|MimeMessage|JavaMailSender|SmtpClient|MailMessage|sgMail|@sendgrid|mailgun|postmark|resend\.emails|ses\.send|SendEmailCommand|sendEmail|send_email|Mail::|ActionMailer|mail\(|PHPMailer|Mailer\b)",
    "SMS_CALL": r"(?i:twilio|\.messages\.create\(|sns\.publish|sendSms|send_sms|vonage|nexmo|messagebird|plivo|sinch)",
}

RULES = [
    {
        "id": "mail-header-from-request", "check_id": "MAIL-HDR-001", "title": "Email header/recipient set from request data",
        "files": ["code"],
        "pattern": r"(?i)\b(to|cc|bcc|subject|replyTo|reply_to|headers|recipients?)\b['\"]?\s*[:=]\s*[^,\n]*({{SRC}})",
        "near": {"pattern": "{{MAIL_CALL}}", "lines": 8}, "confidence": "MEDIUM",
        "note": "Validate addresses, strip CR/LF from all header values, and prefer the library's structured fields.",
        "examples": {"match": ["await transporter.sendMail({ to: admin, subject: req.body.subject, text });"], "no_match": ["await transporter.sendMail({ to: admin, subject: 'New contact request', text });"]},
    },
    {
        "id": "mail-python-header-assign", "check_id": "MAIL-HDR-001", "title": "Raw email header assigned from request data (Python)",
        "files": ["py"], "pattern": r"\bmsg\[['\"](To|From|Subject|Cc|Bcc|Reply-To)['\"]\]\s*=\s*[^\n]*({{SRC_PY}})",
        "confidence": "HIGH", "examples": {"match": ["msg['Subject'] = request.form['subject']"], "no_match": ["msg['Subject'] = 'Welcome'"]},
    },
    {
        "id": "mail-php-mail-input", "check_id": "MAIL-HDR-001", "title": "PHP mail() with request data", "files": ["php"],
        "pattern": r"\bmail\(\s*[^;]*\$_(GET|POST|REQUEST)", "confidence": "HIGH",
        "examples": {"match": ["mail($_POST['to'], $_POST['subject'], $body);"], "no_match": ["mail(ADMIN, 'Contact', $body);"]},
    },
    {
        "id": "mail-from-user", "check_id": "MAIL-SPOOF-001", "title": "Sender address taken from the request",
        "files": ["code"], "pattern": r"(?i)\b(from|sender|from_email|fromEmail)\b['\"]?\s*[:=]\s*[^,\n]*({{SRC}})",
        "near": {"pattern": "{{MAIL_CALL}}", "lines": 8}, "confidence": "HIGH",
        "note": "Send from your own domain; put the user's address in Reply-To after validation.",
        "examples": {"match": ["await sgMail.send({ to: SUPPORT, from: req.body.email, text });"], "no_match": ["await sgMail.send({ to: SUPPORT, from: 'noreply@example.com', replyTo: email, text });"]},
    },
    {
        "id": "mail-html-interpolated", "check_id": "MAIL-HTML-001", "title": "User data interpolated into email HTML without escaping",
        "files": ["code"],
        "pattern": r"(?i)\bhtml\w*['\"]?\s*[:=]\s*(`[^`]*\$\{|f['\"][^'\"\n]*\{|['\"][^'\"\n]*['\"]\s*\+)",
        "near": {"pattern": "{{MAIL_CALL}}|{{SRC}}", "lines": 6}, "not_near": {"pattern": r"(?i)(escape|sanitize|encode|DOMPurify|bleach|htmlspecialchars)", "lines": 3},
        "confidence": "MEDIUM",
        "examples": {"match": ["await transporter.sendMail({ to, html: `<p>Message from ${req.body.name}: ${req.body.message}</p>` });"],
                     "no_match": ["await transporter.sendMail({ to, html: render('contact', { name, message }) });"]},
    },
    {
        "id": "mail-template-unescaped", "check_id": "MAIL-HTML-001", "title": "Unescaped output in an email template",
        "files": ["web", "any"], "path_includes": r"(?i)(mail|email|emails|notification|newsletter)",
        "pattern": r"\{\{\{\s*[\w.]+\s*\}\}\}|<%-\s*[\w.]+|\|\s*safe\b|\{!!\s*\$?[\w.]+\s*!!\}|th:utext=|@Html\.Raw\(|\bv-html\b",
        "confidence": "MEDIUM",
        "examples": {"match": ["<p>Hello {{{ user.name }}}</p>"], "no_match": ["<p>Hello {{ user.name }}</p>"]},
    },
    {
        "id": "mail-template-from-input", "check_id": "MAIL-TPL-001", "title": "Email template compiled from user input",
        "files": ["code"],
        "pattern": r"(Handlebars\.compile|handlebars\.compile|ejs\.render|nunjucks\.renderString|pug\.(render|compile)|mjml2html|mjml\(|_\.template|render_template_string|Template\(|Liquid\w*\.parse|ERB\.new|Velocity\.evaluate)\s*\(\s*[^)\n]*({{SRC}})",
        "confidence": "HIGH",
        "examples": {"match": ["const body = Handlebars.compile(req.body.template)(data);"], "no_match": ["const body = templates.welcome(data);"]},
    },
    {
        "id": "mail-link-host-header", "check_id": "MAIL-LINK-001", "title": "Link in a message built from the request Host header",
        "files": ["code"], "pattern": "{{HOST_HEADER}}",
        "near": {"pattern": r"(?i)(link|url|href|mail|email|invite|verify|reset|confirm|unsubscribe)", "lines": 4}, "confidence": "HIGH",
        "examples": {"match": ["const link = `${req.protocol}://${req.get('host')}/verify?token=${t}`;"], "no_match": ["const link = `${config.appUrl}/verify?token=${t}`;"]},
    },
    {
        "id": "mail-password-in-message", "check_id": "MAIL-TOKEN-001", "title": "Password included in a message",
        "files": ["code", "web"],
        "pattern": r"(?i)(\$\{\s*[\w.]*(password|passwd|temp_?pass\w*)\s*\}|\{\{\s*[\w.]*(password|passwd|temp_?pass\w*)\s*\}\}|\+\s*[\w.]*(password|passwd)\b|\{[\w.]*(password|passwd)\})",
        "near": {"pattern": "{{MAIL_CALL}}|{{SMS_CALL}}|(?i:subject|html|text|body|template)", "lines": 4}, "confidence": "HIGH",
        "examples": {"match": ["text: `Your new password is ${newPassword}`,"], "no_match": ["text: `Reset your password: ${resetLink}`,"]},
    },
    {
        "id": "mail-enumeration", "check_id": "MAIL-ENUM-001", "title": "Message reveals whether an address is registered",
        "files": ["code", "web"],
        "pattern": r"(?i)['\"`][^'\"`]*\b(no\s+account|email\s+(not\s+found|is\s+not\s+registered|does\s*n[o']?t\s+exist)|user\s+not\s+found|not\s+registered|already\s+(registered|exists|in\s+use|taken))[^'\"`]*['\"`]",
        "near": {"pattern": r"(?i)(mail|email|send|invite|reset|forgot|verify)", "lines": 10}, "confidence": "MEDIUM",
        "examples": {"match": ["if (!user) return res.status(404).json({ error: 'No account with that email' });"], "no_match": ["res.json({ message: 'If the address is registered, you will receive an email.' });"]},
    },
    {
        "id": "mail-recipient-from-request", "check_id": "MAIL-RELAY-001", "title": "Arbitrary recipient taken from the request",
        "files": ["code"], "pattern": r"(?i)\b(to|recipients?|cc|bcc)\b['\"]?\s*[:=]\s*({{SRC}})",
        "near": {"pattern": "{{MAIL_CALL}}", "lines": 8}, "confidence": "HIGH",
        "note": "Share/invite/contact features become spam relays unless content is templated and sending is limited.",
        "examples": {"match": ["await mailer.send({ to: req.body.friendEmail, subject: 'Check this out', html: req.body.note });"], "no_match": ["await mailer.send({ to: user.email, subject: 'Welcome', html });"]},
    },
    {
        "id": "mail-no-rate-limit", "check_id": "MAIL-RATE-001", "type": "absence", "scope": "project",
        "title": "Messages sent from request handlers with no rate limiting anywhere", "files": ["code", "config"],
        "when": "{{MAIL_CALL}}|{{SMS_CALL}}", "file_requires": "{{SRC}}", "missing": "{{RATE_LIMIT}}|(?i:cooldown|resend_?after|last_?sent)",
        "confidence": "MEDIUM",
        "examples": {"match": ["app.post('/invite', async (req, res) => { await sendMail({ to: req.body.email }); })"], "no_match": ["app.post('/invite', inviteLimiter, async (req, res) => { await sendMail({ to: req.body.email }); })"]},
    },
    {
        "id": "mail-attachment-path", "check_id": "MAIL-ATTACH-001", "title": "Attachment path/URL taken from the request",
        "files": ["code"],
        "pattern": r"(?i)(attachments?\s*[:=]\s*\[[^\]]*(path|href|filename|content)\s*:\s*({{SRC}})|attach\w*\(\s*({{SRC}})|\b(path|href)\s*:\s*({{SRC}}))",
        "near": {"pattern": "{{MAIL_CALL}}|(?i:attach)", "lines": 6}, "confidence": "HIGH",
        "note": "Nodemailer `path`/`href` read local files or fetch URLs: arbitrary file read or SSRF.",
        "examples": {"match": ["await transporter.sendMail({ to, attachments: [{ path: req.body.file }] });"], "no_match": ["await transporter.sendMail({ to, attachments: [{ filename: 'invoice.pdf', content: pdfBuffer }] });"]},
    },
    {
        "id": "mail-smtp-tls-off", "check_id": "MAIL-SMTP-001", "title": "SMTP without TLS or certificate verification",
        "files": ["code", "config", "env"],
        "pattern": r"(?i)ignoreTLS\s*:\s*true|requireTLS\s*:\s*false|EMAIL_USE_TLS\s*=\s*False|MAIL_USE_TLS\s*=\s*False|smtp\.starttls\.enable\s*=\s*false|ssl_verify_mode\s*[:=]\s*['\"]?none|rejectUnauthorized\s*:\s*false",
        "near": {"pattern": r"(?i)(smtp|mail|transport|email)", "lines": 6}, "confidence": "MEDIUM",
        "examples": {"match": ["nodemailer.createTransport({ host, port: 587, ignoreTLS: true })"], "no_match": ["nodemailer.createTransport({ host, port: 465, secure: true })"]},
    },
    {
        "id": "mail-smtp-password-literal", "check_id": "MAIL-SMTP-001", "title": "Hardcoded SMTP / email provider credential",
        "files": ["code", "config"], "redact": 2,
        "pattern": r"(?i)\b\w*(?:smtp|mail|email|sendgrid|mailgun|postmark|ses)\w*(?:pass|password|pwd|api_?key|secret)\w*['\"]?\s*[:=]\s*['\"](?!\$\{|\{\{|<|your|xxx|changeme)([^'\"\s]{6,})['\"]",
        "confidence": "HIGH",
        "examples": {"match": ["EMAIL_HOST_PASSWORD = 'mailpass123'"], "no_match": ["EMAIL_HOST_PASSWORD = os.environ['EMAIL_HOST_PASSWORD']"]},
    },
    {
        "id": "mail-sms-recipient-from-request", "check_id": "MAIL-SMS-001", "title": "SMS/voice sent to a request-supplied number",
        "files": ["code"], "pattern": r"(?i)\b(to|phone|phoneNumber|PhoneNumber|recipient)\b['\"]?\s*[:=]\s*({{SRC}})",
        "near": {"pattern": "{{SMS_CALL}}", "lines": 6},
        "not_near": {"pattern": r"(?i)(allowed_?countr|allowCountr|libphonenumber|parsePhoneNumber|isValidPhone|phonenumbers\.|geo_?permission)", "lines": 6},
        "confidence": "MEDIUM", "note": "Restrict destination countries and rate-limit to prevent SMS pumping fraud.",
        "examples": {"match": ["await twilio.messages.create({ to: req.body.phone, from: FROM, body: code });"], "no_match": ["const n = parsePhoneNumber(req.body.phone); if (!ALLOWED_COUNTRIES.has(n.country)) throw e;\nawait twilio.messages.create({ to: n.number, from: FROM, body: code });"]},
    },
]
