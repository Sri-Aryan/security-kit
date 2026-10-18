# Deserialization guide

Source: OWASP Deserialization Cheat Sheet. Native object serializers rebuild arbitrary object graphs, and the
classes on the classpath/import path ("gadgets") run code during that process. **If an attacker controls the bytes,
they control execution.** The fix is to exchange *data*, not *objects*.

## Safe replacements

| Platform | Dangerous | Use instead |
|---|---|---|
| Python | `pickle`, `cPickle`, `dill`, `marshal`, `shelve`, `jsonpickle`, `yaml.load`/`full_load`/`unsafe_load`, `torch.load` (pickle), `joblib.load`, `np.load(allow_pickle=True)` | JSON + schema (pydantic), `yaml.safe_load`, `safetensors`, `torch.load(weights_only=True)` |
| Java/Kotlin | `ObjectInputStream.readObject`, `XMLDecoder`, XStream without allow-list, SnakeYAML `new Yaml()` (< 2.0), Jackson default typing, Kryo without registration, Hessian | JSON with concrete types, `ObjectInputFilter` allow-lists if unavoidable, XStream `allowTypes`, SnakeYAML `SafeConstructor` |
| .NET | `BinaryFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling` ≠ None, `JavaScriptSerializer` with type resolver | `System.Text.Json`, `DataContractSerializer` with known types, ViewState MAC + encryption |
| PHP | `unserialize`, `phar://` wrappers on user paths | `json_decode`; `unserialize($x, ['allowed_classes' => false])` if unavoidable |
| Ruby | `Marshal.load`, `YAML.load` (Psych < 4), `Oj` object mode | `JSON.parse`, `YAML.safe_load` |
| JavaScript | `node-serialize`, `serialize-to-js`, `funcster` | `JSON.parse` + schema validation |

## When native deserialization cannot be removed (DESER-ALLOW-001)

Sign the serialized bytes with an HMAC and verify before deserializing; add a strict class allow-list (look-ahead
deserialization / `ObjectInputFilter`); keep gadget libraries updated (DESER-DEPS-001).

## Client-side state (DESER-CLIENT-001)

Anything round-tripped through the browser (cookies, hidden fields, ViewState, JSF state) is attacker-controlled.
Prefer server-side sessions; otherwise sign and encrypt it and verify the MAC first.

## Prototype pollution (DESER-PROTO-001)

In JavaScript, merging attacker objects (`_.merge(target, req.body)`, `for (k in input) target[k] = …`,
`obj[a][b] = v` with request keys) can set `Object.prototype` properties via `__proto__`/`constructor.prototype`,
changing behaviour app-wide (auth bypass, RCE via gadgets in templating/child_process options). Fixes: pick allowed
keys, reject `__proto__`/`constructor`/`prototype`, use `Object.create(null)` or `Map`, keep lodash/merge libraries
updated, consider `Object.freeze(Object.prototype)` at startup.
