"""sk-domain rules: dangling third-party DNS targets, wildcard records, SPF/DMARC/DKIM, CAA, security.txt, cookies."""

SKILL = "sk-domain"

DNS_FILES = ["tf", "config", "code", ".zone", ".db", ".txt"]

MACROS = {
    "DNS_DEF": r"aws_route53_record|cloudflare_record|cloudflare_dns_record|azurerm_dns_\w+_record|google_dns_record_set|digitalocean_record|AWS::Route53::RecordSet|route53\.\w*Record|\bIN\s+(A|AAAA|CNAME|MX|TXT)\s",
    "TAKEOVER_HOST": r"(?i:[\w.-]+\.(s3-website[.-][\w-]+\.amazonaws\.com|s3\.amazonaws\.com|elasticbeanstalk\.com|cloudfront\.net|herokuapp\.com|herokudns\.com|azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azurefd\.net|github\.io|gitlab\.io|netlify\.app|netlify\.com|vercel\.app|vercel-dns\.com|surge\.sh|pantheonsite\.io|ghost\.io|myshopify\.com|zendesk\.com|helpscoutdocs\.com|wpengine\.com|fly\.dev|bitbucket\.io|readthedocs\.io|webflow\.io|statuspage\.io|unbouncepages\.com|ngrok\.io|firebaseapp\.com|web\.app))",
}

RULES = [
    {
        "id": "domain-third-party-target", "check_id": "DOMAIN-TAKEOVER-001", "title": "DNS record points at a third-party service (verify it is still yours)", "files": DNS_FILES,
        "pattern": r"{{TAKEOVER_HOST}}\.?['\"]?",
        "near": {"pattern": r"(?i)CNAME|ALIAS|records?\s*=|\"?value\"?\s*[:=]|content\s*=|\bIN\s+|target|ResourceRecords", "lines": 4},
        "file_requires": "{{DNS_DEF}}", "confidence": "LOW",
        "note": "If the app/bucket/site behind this name is deleted while the record stays, anyone can claim it and serve content on your subdomain.",
        "examples": {"match": ["resource \"aws_route53_record\" \"docs\" {\n  type    = \"CNAME\"\n  records = [\"acme-docs.herokuapp.com\"]\n}"],
                     "no_match": ["resource \"aws_route53_record\" \"api\" {\n  type    = \"A\"\n  records = [aws_eip.api.public_ip]\n}"]},
    },
    {
        "id": "domain-wildcard-record", "check_id": "DOMAIN-TAKEOVER-001", "title": "Wildcard DNS record", "files": DNS_FILES,
        "pattern": r"(?i)\bname\s*[:=]\s*['\"]\*(\.|['\"])|^\s*\*(\.[\w-]+)*\s+(\d+\s+)?(IN\s+)?(A|AAAA|CNAME)\s|\"Name\"\s*:\s*\"\*\.",
        "file_requires": "{{DNS_DEF}}", "confidence": "LOW", "note": "Every subdomain resolves, which widens phishing and takeover surface and hides typos.",
        "examples": {"match": ["resource \"cloudflare_record\" \"all\" {\n  name = \"*\"\n  type = \"CNAME\"\n}"], "no_match": ["resource \"cloudflare_record\" \"www\" {\n  name = \"www\"\n  type = \"CNAME\"\n}"]},
    },
    {
        "id": "domain-spf-permissive", "check_id": "DOMAIN-SPF-001", "title": "SPF record that allows anyone to send", "files": DNS_FILES,
        "pattern": r"(?i)v=spf1[^\"'\n]*\s[+?]all\b|v=spf1\s+\+?all\b", "confidence": "HIGH",
        "examples": {"match": ["  records = [\"v=spf1 include:_spf.google.com +all\"]", "@ IN TXT \"v=spf1 ?all\""], "no_match": ["  records = [\"v=spf1 include:_spf.google.com -all\"]"]},
    },
    {
        "id": "domain-dmarc-none", "check_id": "DOMAIN-DMARC-001", "title": "DMARC policy set to none", "files": DNS_FILES,
        "pattern": r"(?i)v=DMARC1;\s*p=none\b", "confidence": "MEDIUM", "note": "p=none only monitors; move to quarantine/reject once reports are clean.",
        "examples": {"match": ["  records = [\"v=DMARC1; p=none; rua=mailto:dmarc@acme.com\"]"], "no_match": ["  records = [\"v=DMARC1; p=reject; rua=mailto:dmarc@acme.com\"]"]},
    },
    {
        "id": "domain-no-dmarc", "check_id": "DOMAIN-DMARC-001", "type": "absence", "scope": "project",
        "title": "SPF defined but no DMARC record anywhere", "files": DNS_FILES,
        "when": r"(?i)v=spf1", "missing": r"(?i)v=DMARC1", "confidence": "LOW",
        "examples": {"match": ["resource \"aws_route53_record\" \"spf\" {\n  records = [\"v=spf1 include:mailgun.org -all\"]\n}"],
                     "no_match": ["resource \"aws_route53_record\" \"spf\" {\n  records = [\"v=spf1 include:mailgun.org -all\"]\n}\n# _dmarc: v=DMARC1; p=reject"]},
    },
    {
        "id": "domain-dkim-short-key", "check_id": "DOMAIN-DKIM-001", "title": "DKIM public key that looks 1024-bit or shorter", "files": DNS_FILES,
        "pattern": r"(?i)v=DKIM1;[^\"'\n]*\bp=[A-Za-z0-9+/]{100,250}={0,2}\s*[\"';]", "confidence": "LOW",
        "examples": {"match": ["  records = [\"v=DKIM1; k=rsa; p=" + "A" * 216 + "\"]"], "no_match": ["  records = [\"v=DKIM1; k=rsa; p=" + "A" * 392 + "\"]"]},
    },
    {
        "id": "domain-no-caa", "check_id": "DOMAIN-CAA-001", "type": "absence", "scope": "project",
        "title": "DNS zone managed in code without CAA records", "files": DNS_FILES,
        "when": "{{DNS_DEF}}", "missing": r"(?i)\bCAA\b", "confidence": "LOW",
        "examples": {"match": ["resource \"aws_route53_record\" \"www\" {\n  type = \"CNAME\"\n}"], "no_match": ["resource \"aws_route53_record\" \"caa\" {\n  type    = \"CAA\"\n  records = [\"0 issue \\\"letsencrypt.org\\\"\"]\n}"]},
    },
    {
        "id": "domain-security-txt-incomplete", "check_id": "DOMAIN-SECTXT-001", "type": "absence", "scope": "file",
        "title": "security.txt without an Expires field", "files": ["any"], "path_includes": r"(?i)security\.txt$",
        "when": r"(?im)^Contact:", "missing": r"(?im)^Expires:", "confidence": "MEDIUM",
        "examples": {"match": ["Contact: mailto:security@acme.com\nPreferred-Languages: en"], "no_match": ["Contact: mailto:security@acme.com\nExpires: 2027-06-30T00:00:00.000Z"]},
    },
    {
        "id": "domain-parent-domain-cookie", "check_id": "DOMAIN-COOKIE-001", "title": "Cookie scoped to the parent domain", "files": ["code", "config"],
        "pattern": r"(?i)\bdomain\s*:\s*['\"]\.?[\w-]+\.[\w.-]+['\"]|;\s*Domain=\.?[\w-]+\.[\w.-]+|SESSION_COOKIE_DOMAIN\s*=\s*['\"]\.[\w.-]+['\"]|cookie_domain\s*[:=]\s*['\"]\.[\w.-]+|setDomain\(\s*\"\.?[\w-]+\.[\w.-]+\"\s*\)",
        "near": {"pattern": r"(?i)cookie|session", "lines": 4}, "confidence": "MEDIUM",
        "note": "Every subdomain (including a taken-over one or a user-content host) can read and overwrite it. Prefer host-only cookies (no Domain attribute) or the __Host- prefix.",
        "examples": {"match": ["app.use(session({ cookie: { domain: '.acme.com', secure: true } }));", "SESSION_COOKIE_DOMAIN = '.acme.com'"],
                     "no_match": ["app.use(session({ cookie: { secure: true, httpOnly: true } }));"]},
    },
]
