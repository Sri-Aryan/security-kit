"""sk-saml rules: disabled validation, cert from KeyInfo, SHA-1, manual parsing, RelayState, replay, linking."""

SKILL = "sk-saml"

SAML_CTX = r"(?i)saml|SAMLResponse|passport-saml|node-saml|samlify|onelogin|ruby-saml|Saml2|pysaml2|AuthnRequest"

RULES = [
    {
        "id": "saml-signature-checks-off", "check_id": "SAML-SIG-001", "title": "SAML signature validation weakened or disabled", "files": ["code", "config"],
        "pattern": r"(?i)want_?Assertions_?Signed['\"]?\s*[:=]\s*(false|False)|want_?(Authn_?)?Response_?Signed['\"]?\s*[:=]\s*(false|False)|validate_?Signature['\"]?\s*[:=]\s*(false|False)|['\"]strict['\"]\s*[:=]\s*(false|False)|skip_?signature\w*\s*[:=]\s*(true|True)|signature_?validation\w*\s*[:=]\s*(false|False)|allow_?unsigned\w*\s*[:=]\s*(true|True)|wantMessagesSigned['\"]?\s*:\s*false|setWantAssertionsSigned\(\s*false\s*\)",
        "file_requires": SAML_CTX, "confidence": "HIGH",
        "examples": {"match": ["const saml = new SAML({ cert, wantAssertionsSigned: false }); // passport-saml", "settings = { 'strict': False, 'sp': sp, 'idp': idp }  # onelogin saml"],
                     "no_match": ["const saml = new SAML({ idpCert: IDP_CERT, wantAssertionsSigned: true, wantAuthnResponseSigned: true }); // node-saml"]},
    },
    {
        "id": "saml-conditions-off", "check_id": "SAML-COND-001", "title": "SAML audience, destination or time checks disabled", "files": ["code", "config"],
        "pattern": r"(?i)\baudience\s*:\s*false|skip_?(audience|recipient|destination|subject_?confirmation|conditions)\w*\s*[:=]\s*(true|True)|acceptedClockSkewMs\s*:\s*(-1|\d{7,})|allowed_?clock_?drift\s*[:=]\s*\d{4,}|validateInResponseTo\s*:\s*['\"]?(never|false)|reject_?deprecated_?algorithm\s*[:=]\s*False",
        "file_requires": SAML_CTX, "confidence": "HIGH",
        "examples": {"match": ["new SAML({ idpCert, audience: false, acceptedClockSkewMs: -1 }) // node-saml"], "no_match": ["new SAML({ idpCert, audience: 'https://app.acme.com/saml', acceptedClockSkewMs: 5000 }) // node-saml"]},
    },
    {
        "id": "saml-cert-from-keyinfo", "check_id": "SAML-CERT-001", "title": "Signing certificate read from the SAML message itself", "files": ["code"],
        "pattern": r"(?i)(getElementsByTagName(NS)?\([^)]*X509Certificate|xpath[^\n]*X509Certificate|find(all)?\([^)]*X509Certificate|\.KeyInfo\b[^\n]*(cert|Certificate)|SelectSingleNode\([^)]*X509Certificate)",
        "confidence": "HIGH", "note": "An attacker signs a forged assertion with their own key and puts their certificate in KeyInfo. Use the IdP certificate from configured metadata.",
        "examples": {"match": ["const cert = doc.getElementsByTagName('ds:X509Certificate')[0].textContent;"], "no_match": ["const cert = config.idp.signingCert;"]},
    },
    {
        "id": "saml-sha1", "check_id": "SAML-CERT-001", "title": "SHA-1 signature or digest algorithm allowed", "files": ["code", "config"],
        "pattern": r"(?i)xmldsig#rsa-sha1|xmldsig#sha1|(signatureAlgorithm|digestAlgorithm|signature_algorithm|digest_algorithm)['\"]?\s*[:=]\s*['\"]?sha1\b|SecurityAlgorithms\.RsaSha1Signature",
        "file_requires": SAML_CTX, "confidence": "MEDIUM",
        "examples": {"match": ["signatureAlgorithm: 'sha1', // saml"], "no_match": ["signatureAlgorithm: 'sha256', // saml"]},
    },
    {
        "id": "saml-manual-parsing", "check_id": "SAML-WRAP-001", "title": "Identity read from SAML XML by hand (signature wrapping risk)", "files": ["code"],
        "pattern": r"(?i)(getElementsByTagName(NS)?|xpath|find|findall|SelectSingleNode|SelectNodes|at_xpath|css)\(\s*[^)]*['\"][^'\"]*(NameID|AttributeValue|Attribute\b|saml2?:Assertion|Subject)['\"]",
        "file_requires": SAML_CTX, "confidence": "MEDIUM",
        "note": "XPath finds the first matching element, which may not be the signed one. Use the library's validated profile/attributes only.",
        "examples": {"match": ["const email = doc.getElementsByTagName('saml:NameID')[0].textContent; // SAMLResponse"], "no_match": ["const { profile } = await saml.validatePostResponseAsync(req.body); // SAMLResponse"]},
    },
    {
        "id": "saml-unsafe-xml-parser", "check_id": "SAML-XML-001", "title": "SAML message parsed with a default XML parser", "files": ["code"],
        "pattern": r"(etree\.fromstring|etree\.parse|minidom\.parseString|xml2js\.parseString|parseStringPromise|new\s+DOMParser\(\)|DocumentBuilderFactory\.newInstance\(\)|new\s+XmlDocument\(\)|Nokogiri::XML\(|simplexml_load_string\()",
        "near": {"pattern": r"SAMLResponse|SAMLRequest|saml", "lines": 6},
        "not_near": {"pattern": r"(?i)defused|resolve_entities\s*=\s*False|disallow-doctype-decl|XmlResolver\s*=\s*null|DtdProcessing\.Prohibit|NONET|noent\s*:\s*false|LIBXML_NONET", "lines": 6},
        "confidence": "MEDIUM",
        "examples": {"match": ["xml = base64.b64decode(request.form['SAMLResponse'])\nroot = etree.fromstring(xml)"],
                     "no_match": ["xml = base64.b64decode(request.form['SAMLResponse'])\nroot = defusedxml.ElementTree.fromstring(xml)"]},
    },
    {
        "id": "saml-relaystate-redirect", "check_id": "SAML-RELAY-001", "title": "Redirect to RelayState without validation", "files": ["code"],
        "pattern": r"(?i)(redirect|redirect_to|sendRedirect|Redirect|res\.redirect|location\.href\s*=)\s*\(?[^\n]*RelayState",
        "not_near": {"pattern": r"(?i)safeRedirect|isSafe|is_safe_url|url_has_allowed_host|allow_?list|allowlist|startsWith\(\s*['\"]/['\"]|IsLocalUrl|new URL\(", "lines": 3},
        "confidence": "MEDIUM",
        "examples": {"match": ["res.redirect(req.body.RelayState || '/');"], "no_match": ["res.redirect(safeRedirect(req.body.RelayState));"]},
    },
    {
        "id": "saml-no-replay-protection", "check_id": "SAML-REPLAY-001", "type": "absence", "scope": "project",
        "title": "SAML used but no InResponseTo/replay cache found", "files": ["code", "config"],
        "when": r"passport-saml|@node-saml|samlify|python3-saml|onelogin\.saml|OneLogin_Saml2|ruby-saml|OneLogin::RubySaml|pysaml2|saml2\.client|Sustainsys|ITfoxtec|Saml2Configuration|spring-security-saml|Saml2LoginConfigurer",
        "missing": r"(?i)InResponseTo|validateInResponseTo|cacheProvider|replay|used_?assertion|assertion_?id|requestIdExpirationPeriodMs|ReplayCache|get_last_assertion_id|last_assertion_id|outstanding_queries",
        "confidence": "LOW",
        "examples": {"match": ["const { SAML } = require('@node-saml/node-saml');"], "no_match": ["const { SAML } = require('@node-saml/node-saml');\nconst saml = new SAML({ validateInResponseTo: 'always', cacheProvider });"]},
    },
    {
        "id": "saml-link-by-email", "check_id": "SAML-LINK-001", "title": "SAML user matched by email or NameID across all tenants", "files": ["code"],
        "pattern": r"(?i)(findOne|findUnique|findFirst|find_by|filter_by|findByEmail|get_by_email|where|objects\.get)\(?[^\n]*(profile\.(email|nameID|mail)|attributes\s*\[\s*['\"][^'\"]*(email|mail|emailaddress)|name_?id\b|nameID\b|get_nameid\(\))",
        "not_near": {"pattern": r"(?i)(tenant|org_?id|organization|idp_?id|issuer|entity_?id|connection_?id)", "lines": 3},
        "confidence": "MEDIUM", "note": "Scope the lookup to the IdP/tenant that sent the assertion, so one customer's IdP can't sign in another customer's users.",
        "examples": {"match": ["const user = await User.findOne({ where: { email: profile.email } });"],
                     "no_match": ["const user = await User.findOne({ where: { email: profile.email, orgId: connection.orgId } });"]},
    },
]
