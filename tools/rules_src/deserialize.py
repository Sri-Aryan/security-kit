"""sk-deserialize rules."""

SKILL = "sk-deserialize"

MACROS = {
    "UNTRUSTED": r"{{SRC}}|(?i:request|body|payload|cookie|header|upload|socket|recv|message|queue|redis|cache|base64|b64decode|decode\()",
}

RULES = [
    {
        "id": "deser-pickle", "check_id": "DESER-NATIVE-001", "title": "pickle/marshal/shelve/dill deserialization", "files": ["py"],
        "pattern": r"\b(pickle|cPickle|_pickle|dill|cloudpickle)\.loads?\(|\bmarshal\.loads?\(|\bshelve\.open\(|\bjsonpickle\.decode\(|pandas\.read_pickle\(|\bpd\.read_pickle\(",
        "confidence": "HIGH", "note": "Loading attacker-controlled pickle data executes arbitrary code. Use JSON or a schema format.",
        "examples": {"match": ["obj = pickle.loads(request.data)", "session = pickle.loads(base64.b64decode(cookie))"], "no_match": ["obj = json.loads(request.data)"]},
    },
    {
        "id": "deser-java-ois", "check_id": "DESER-NATIVE-001", "title": "Java native deserialization", "files": ["java", "kt", "scala"],
        "pattern": r"new\s+ObjectInputStream\(|\.readObject\(\)|\.readUnshared\(\)|SerializationUtils\.deserialize\(|readResolve|RemoteObjectInvocationHandler|HessianInput|Hessian2Input|KryoSerializer|new\s+Kryo\(\)",
        "not_near": {"pattern": r"(ObjectInputFilter|setObjectInputFilter|ValidatingObjectInputStream|LookAheadObjectInputStream|accept\(|SerialKiller)", "lines": 6},
        "confidence": "HIGH",
        "examples": {"match": ["ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nObject o = in.readObject();"], "no_match": ["ValidatingObjectInputStream in = new ValidatingObjectInputStream(s);\nin.accept(Order.class);"]},
    },
    {
        "id": "deser-dotnet", "check_id": "DESER-NATIVE-001", "title": ".NET dangerous formatter", "files": ["cs"],
        "pattern": r"\b(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter|JavaScriptSerializer\(\s*new\s+SimpleTypeResolver)\b",
        "confidence": "HIGH", "examples": {"match": ["var obj = new BinaryFormatter().Deserialize(stream);"], "no_match": ["var obj = JsonSerializer.Deserialize<Order>(json);"]},
    },
    {
        "id": "deser-php-unserialize", "check_id": "DESER-NATIVE-001", "title": "PHP unserialize()", "files": ["php"],
        "pattern": r"\bunserialize\(\s*(?![^)]*allowed_classes\s*=>\s*false)|phar://", "confidence": "HIGH",
        "examples": {"match": ["$cart = unserialize($_COOKIE['cart']);"], "no_match": ["$cart = json_decode($_COOKIE['cart'], true);"]},
    },
    {
        "id": "deser-ruby-marshal", "check_id": "DESER-NATIVE-001", "title": "Ruby Marshal / Oj object mode", "files": ["rb"],
        "pattern": r"\bMarshal\.(load|restore)\(|\bOj\.(load|object_load)\((?![^)]*mode:\s*:(strict|null|compat))", "confidence": "HIGH",
        "examples": {"match": ["obj = Marshal.load(Base64.decode64(params[:state]))"], "no_match": ["obj = JSON.parse(params[:state])"]},
    },
    {
        "id": "deser-node-serialize", "check_id": "DESER-NATIVE-001", "title": "Unsafe JavaScript (de)serialization library", "files": ["js"],
        "pattern": r"require\(\s*['\"](node-serialize|serialize-to-js|funcster|cryo)['\"]\)|from\s+['\"](node-serialize|serialize-to-js|funcster|cryo)['\"]|\.unserialize\(",
        "confidence": "HIGH", "examples": {"match": ["const serialize = require('node-serialize');\nconst obj = serialize.unserialize(req.cookies.profile);"], "no_match": ["const obj = JSON.parse(req.cookies.profile);"]},
    },
    {
        "id": "deser-yaml-unsafe-py", "check_id": "DESER-YAML-001", "title": "Unsafe YAML load (Python)", "files": ["py"],
        "pattern": r"yaml\.load\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)|yaml\.unsafe_load\(|yaml\.full_load\(|yaml\.load_all\((?![^)]*Safe)|Loader\s*=\s*(yaml\.)?(Unsafe|Full)?Loader\b(?!.*Safe)",
        "confidence": "HIGH", "examples": {"match": ["cfg = yaml.load(request.data, Loader=yaml.Loader)", "data = yaml.unsafe_load(f)"], "no_match": ["cfg = yaml.safe_load(request.data)"]},
    },
    {
        "id": "deser-yaml-unsafe-other", "check_id": "DESER-YAML-001", "title": "Unsafe YAML load (Java/Ruby/JS)", "files": ["java", "kt", "rb", "js"],
        "pattern": r"new\s+Yaml\(\s*\)|new\s+Yaml\(\s*new\s+Constructor\(|\bYAML\.load\((?![^)]*permitted_classes)|Psych\.(load|unsafe_load)\(|YAML\.unsafe_load\(|yaml\.load\([^)]*schema\s*:\s*(yaml\.)?DEFAULT_FULL_SCHEMA|js-yaml[\s\S]{0,40}loadAll?\([^)]*FULL",
        "confidence": "HIGH", "examples": {"match": ["Yaml yaml = new Yaml();\nObject o = yaml.load(input);", "config = YAML.load(params[:yaml])"], "no_match": ["Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));"]},
    },
    {
        "id": "deser-json-polymorphic", "check_id": "DESER-JSON-001", "title": "Polymorphic JSON type handling enabled", "files": ["java", "kt", "cs", "py", "scala"],
        "pattern": r"enableDefaultTyping\(|activateDefaultTyping\(|@JsonTypeInfo\(\s*use\s*=\s*JsonTypeInfo\.Id\.(CLASS|MINIMAL_CLASS)|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)|ParserConfig\.getGlobalInstance\(\)\.setAutoTypeSupport\(\s*true|Feature\.SupportAutoType|jsonpickle\.decode\(",
        "confidence": "HIGH", "examples": {"match": ["mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL);", "TypeNameHandling = TypeNameHandling.All"], "no_match": ["TypeNameHandling = TypeNameHandling.None"]},
    },
    {
        "id": "deser-xml-decoder", "check_id": "DESER-XML-001", "title": "XML object deserializer", "files": ["java", "kt", "cs"],
        "pattern": r"new\s+XMLDecoder\(|new\s+XStream\(|xstream\.fromXML\(|\.fromXML\(|new\s+XmlSerializer\(\s*Type\.GetType\(",
        "not_near": {"pattern": r"(allowTypes|addPermission|NoTypePermission|setupDefaultSecurity|allowTypesByWildcard)", "lines": 6},
        "confidence": "HIGH", "examples": {"match": ["XStream xs = new XStream();\nObject o = xs.fromXML(body);"], "no_match": ["XStream xs = new XStream();\nxs.addPermission(NoTypePermission.NONE);\nxs.allowTypes(new Class[]{Order.class});"]},
    },
    {
        "id": "deser-from-untrusted", "check_id": "DESER-ALLOW-001", "title": "Deserialization fed directly from request/cookie/queue data", "files": ["code"],
        "pattern": r"(pickle\.loads?|unserialize|Marshal\.load|readObject|Deserialize|yaml\.load|fromXML|jsonpickle\.decode)\s*\([^)\n]*({{UNTRUSTED}})",
        "not_near": {"pattern": r"(?i)(hmac|verify|signature|ObjectInputFilter|allowed_classes|safe)", "lines": 3}, "confidence": "HIGH",
        "examples": {"match": ["state = pickle.loads(base64.b64decode(request.cookies['state']))"], "no_match": ["state = json.loads(base64.b64decode(request.cookies['state']))"]},
    },
    {
        "id": "deser-viewstate-mac-off", "check_id": "DESER-CLIENT-001", "title": "Client-side serialized state without integrity protection", "files": ["config", "cs", "web", "java"],
        "pattern": r"(?i)enableViewStateMac\s*=\s*\"false\"|ViewStateEncryptionMode\s*=\s*\"Never\"|aspnet:AllowInsecureDeserialization|org\.apache\.myfaces\.USE_ENCRYPTION[\s\S]{0,60}false|javax\.faces\.STATE_SAVING_METHOD[\s\S]{0,60}client",
        "confidence": "HIGH", "examples": {"match": ["<pages enableViewStateMac=\"false\" />"], "no_match": ["<pages enableViewStateMac=\"true\" />"]},
    },
    {
        "id": "deser-torch-load", "check_id": "DESER-MODEL-001", "title": "Model/array loaded with pickle-based loader", "files": ["py"],
        "pattern": r"torch\.load\((?![^)]*weights_only\s*=\s*True)|joblib\.load\(|numpy\.load\([^)]*allow_pickle\s*=\s*True|np\.load\([^)]*allow_pickle\s*=\s*True|keras\.models\.load_model\([^)]*safe_mode\s*=\s*False|pickle\.load\(\s*open\([^)]*\.(pkl|pt|pth|bin|joblib)",
        "confidence": "MEDIUM", "note": "Prefer safetensors; with PyTorch pass weights_only=True; only load models from trusted, pinned sources.",
        "examples": {"match": ["model = torch.load(path)", "clf = joblib.load(uploaded_path)"], "no_match": ["model = torch.load(path, weights_only=True)"]},
    },
    {
        "id": "deser-proto-merge", "check_id": "DESER-PROTO-001", "title": "Untrusted object deep-merged/assigned (prototype pollution)", "files": ["js"],
        "pattern": r"\b(_\.|lodash\.)?(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|extend|deepmerge|deepMerge|assignIn)\(\s*[^,)\n]+,\s*([^)\n]*)({{SRC_JS}}|JSON\.parse\()|\$\.extend\(\s*true\s*,[^)\n]*({{SRC_JS}})",
        "not_near": {"pattern": r"(__proto__|Object\.create\(null\)|hasOwnProperty|structuredClone|isSafeKey)", "lines": 3}, "confidence": "MEDIUM",
        "examples": {"match": ["_.merge(settings, req.body);", "deepMerge(config, JSON.parse(input));"], "no_match": ["Object.assign(settings, pick(req.body, ['theme', 'lang']));"]},
    },
    {
        "id": "deser-proto-dynamic-keys", "check_id": "DESER-PROTO-001", "title": "Dynamic property assignment with request-controlled keys", "files": ["js"],
        "pattern": r"for\s*\(\s*(const|let|var)\s+(\w+)\s+in\s+({{SRC_JS}}|JSON\.parse\()|\w+\[\s*({{SRC_JS}})[^\]]*\]\s*(\[[^\]]+\])?\s*=(?!=)",
        "not_near": {"pattern": r"(__proto__|constructor|prototype|hasOwnProperty|Object\.create\(null\)|new Map\()", "lines": 3}, "confidence": "MEDIUM",
        "examples": {"match": ["for (const k in req.body) target[k] = req.body[k];", "obj[req.query.key][req.query.sub] = req.query.value;"], "no_match": ["const m = new Map(); for (const k in req.body) m.set(k, req.body[k]);"]},
    },
    {
        "id": "deser-gadget-libs", "check_id": "DESER-DEPS-001", "title": "Library with known deserialization gadget history", "files": ["config", "any"],
        "pattern": r"(?i)commons-collections[^\n]{0,40}3\.[0-2]\b|<artifactId>commons-collections</artifactId>|fastjson[^\n]{0,30}1\.2\.\d+|\"node-serialize\"|snakeyaml[^\n]{0,30}1\.\d+|xstream[^\n]{0,30}1\.4\.([0-9]|1[0-9])\b",
        "path_includes": r"(?i)(pom\.xml|build\.gradle|package\.json|requirements|Gemfile|\.csproj|go\.mod)", "confidence": "LOW",
        "examples": {"match": ["<artifactId>commons-collections</artifactId>"], "no_match": ["<artifactId>commons-collections4</artifactId>"]},
    },
]
