# Deserialization checklist

Source of truth for `sk-deserialize` check IDs. Covers turning bytes/text from outside the process into objects,
in any language: native serializers, YAML, polymorphic JSON/XML, serialized state stored on the client, ML model
files, and JavaScript prototype pollution through object merging. Based on the OWASP Deserialization Cheat Sheet
and OWASP A08:2021 (Software and Data Integrity Failures). `references/guide.md` lists safe APIs per platform.

Columns: **Mode** S = static. OWASP = OWASP Top 10 2021.

| ID | Check | Mode | Severity | OWASP | CWE |
|---|---|---|---|---|---|
| DESER-NATIVE-001 | Untrusted data is never deserialized with native object serializers (Java `ObjectInputStream`, .NET `BinaryFormatter`/`NetDataContractSerializer`/`SoapFormatter`/`LosFormatter`, Python `pickle`/`marshal`/`shelve`/`dill`/`joblib`, PHP `unserialize`, Ruby `Marshal`, Node `node-serialize`) | S | Critical | A08 | CWE-502 |
| DESER-YAML-001 | YAML from untrusted sources is loaded with safe loaders (`yaml.safe_load`, SnakeYAML `SafeConstructor`, `YAML.safe_load`, js-yaml safe schema) | S | High | A08 | CWE-502 |
| DESER-JSON-001 | Polymorphic type handling in JSON is disabled or allow-listed (Jackson default typing / `@JsonTypeInfo(use = CLASS)`, Json.NET `TypeNameHandling`, fastjson `autoType`, `jsonpickle`) | S | High | A08 | CWE-502 |
| DESER-XML-001 | XML object deserializers are not used on untrusted data (`XMLDecoder`, XStream without allow-lists, `XmlSerializer` with attacker-controlled types) | S | High | A08 | CWE-502 |
| DESER-ALLOW-001 | Where native deserialization is unavoidable, class allow-lists (look-ahead / `ObjectInputFilter`) and integrity checks (HMAC) are enforced before deserializing | S | High | A08 | CWE-502 |
| DESER-CLIENT-001 | Serialized state kept on the client (cookies, hidden fields, ViewState, tokens) is signed/encrypted and verified before use | S | High | A08 | CWE-565 |
| DESER-MODEL-001 | Machine-learning models and checkpoints from untrusted sources are loaded safely (`safetensors`, `torch.load(weights_only=True)`, no pickle-based formats, no `allow_pickle=True`) | S | High | A08 | CWE-502 |
| DESER-PROTO-001 | Untrusted objects are not merged/assigned into other objects without blocking `__proto__`, `constructor` and `prototype` keys (prototype pollution) | S | High | A08 | CWE-1321 |
| DESER-DEPS-001 | Known gadget-chain libraries and vulnerable serializer versions are updated (commons-collections, older Jackson/fastjson/SnakeYAML/XStream) | S | Medium | A06 | CWE-1104 |
