# Injection guide: the safe API per interpreter

Sources: OWASP Injection Prevention, SQL Injection Prevention, Query Parameterization, OS Command Injection
Defense, LDAP Injection Prevention, XML External Entity Prevention, Logging cheat sheets.

**Injection happens whenever data is concatenated into text that another interpreter parses.** The fix is always
the same idea: keep code and data in separate channels (parameters, argument arrays, encoders). Input validation and
escaping are secondary layers.

| Class | Unsafe | Safe |
|---|---|---|
| SQL (INJ-SQL, INJ-ORM) | `"… WHERE id=" + id`, f-strings, `%`, `.format`, template literals, `Sprintf`, `$"…{x}"` | bound parameters (`?`, `$1`, `:name`), ORM query builders, tagged templates (`sql\`\``, `$queryRaw\`\``), allow-listed identifiers |
| NoSQL (INJ-NOSQL) | `find({ email: req.body.email })` where body may be `{"$ne":null}`; `$where` | cast to string / schema validation, `$eq`, `sanitizeFilter`, no server-side JS |
| OS command (INJ-CMD, INJ-ARG) | `exec("ping " + host)`, `shell=True`, `sh -c` | `execFile`/`subprocess.run([...])`/`exec.Command(prog, args...)` without a shell; `--` before user arguments; allow-list values |
| Code (INJ-CODE) | `eval`, `new Function`, `vm`, `exec`, `require(userPath)`, `getattr(obj, user)` | lookup tables / maps of allowed handlers; never evaluate input |
| Templates (INJ-SSTI) | `render_template_string(user)`, `Handlebars.compile(user)`, `ejs.render(user)` | fixed template files; user data only as variables; sandboxed engines for user-authored templates |
| Expression languages (INJ-EL) | `parser.parseExpression(userInput)` (SpEL, OGNL, MVEL, JEXL) | never evaluate user expressions; use a restricted DSL |
| LDAP (INJ-LDAP) | `"(uid=" + user + ")"` | the library's filter/DN escaping (`escape_filter_chars`, `LdapEncoder`, `ldap.filter.escape`), parameterized filters |
| XPath (INJ-XPATH) | `"//user[name='" + n + "']"` | XPath variables/parameters, or strict allow-lists |
| XML (INJ-XXE) | default parsers with DTDs/entities | disable DTDs/external entities (`disallow-doctype-decl`), `defusedxml`, `noent: false` |
| Headers (INJ-HDR) | `setHeader('X', userValue)` | strip CR/LF, encode values (RFC 5987 for filenames) |
| Logs (INJ-LOG) | `log("user=" + name)` | structured logging; encode CR/LF/control characters |
| Regex (INJ-REGEX) | `new RegExp(userInput)` | escape (`re.escape`, `escapeRegExp`) or use plain string search; linear-time engines (RE2); timeouts |
| Paths (INJ-PATH) | `path.join(base, userName)` | generated names; `basename`; resolve then verify the result is inside `base` |
| CSV (INJ-CSV) | cells starting with `=`, `+`, `-`, `@` | prefix such cells with `'` and quote fields |

## Verifying a candidate

Trace the value from its source (request, file, message queue, database row written by users) to the sink. If any
user-controlled part reaches the interpreter as text, it is a finding, even if "validated" by a denylist. Confirm the
interpreter actually parses it (e.g. a parameterized query with a concatenated *table name* is still vulnerable).
