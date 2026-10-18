# Input validation guide

Sources: OWASP Input Validation and Mass Assignment cheat sheets; API3:2023 (object property level authorization).

Validation answers "is this input what we expect?" at the boundary, before any business logic runs. It is not a
replacement for parameterized queries or output encoding (`/sk-inject`, `/sk-xss`), but it removes whole classes
of bugs: mass assignment, type confusion, absurd numbers, malformed formats.

## The pattern (VAL-SCHEMA-001, VAL-STRICT-001)

1. Define a schema per endpoint/message: types, required fields, lengths, ranges, formats, enums.
2. **Parse, don't just check**: use the parsed result, which has unknown fields stripped or rejected.
3. Reject with 400/422 and a generic message; log the failure (aggregate).

| Stack | Library |
|---|---|
| TypeScript/JS | zod (`.strict()`), valibot, ajv (`additionalProperties: false`), joi, class-validator + NestJS `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`, Fastify route schemas |
| Python | pydantic (`model_config = ConfigDict(extra='forbid')`), FastAPI models, DRF serializers, marshmallow (`unknown = RAISE`) |
| Java/Kotlin | Bean Validation (`@Valid`, `@NotNull`, `@Size`, `@Min/@Max`, `@Email`) on DTOs; Jackson `FAIL_ON_UNKNOWN_PROPERTIES` |
| .NET | DataAnnotations or FluentValidation on DTOs; `[ApiController]` automatic 400 |
| Go | go-playground/validator struct tags; `json.Decoder.DisallowUnknownFields()` |
| Ruby/PHP | strong parameters (`params.require(...).permit(...)`), dry-validation; Laravel FormRequest `rules()`, `$fillable` |

## Mass assignment (VAL-MASS-001)

Never pass `req.body` / `request.json` / `params` straight to `create`/`update`/constructors or spread it into a model.
Use an input DTO or explicit field list. Never turn off framework protection (`$guarded = []`, `params.permit!`).
Privileged fields (role, isAdmin, ownerId, tenantId, price, balance, verified) are set only by server code.

## Types, numbers, formats (VAL-TYPE-001, VAL-NUMERIC-001, VAL-FORMAT-001)

- Strict comparisons (`===`, `hash_equals`); reject arrays/objects where scalars are expected (query parsers create them).
- Numbers: integer check, range (min/max), reject NaN/Infinity; money as integer cents or decimal types.
- Formats: library validators (zod `.email()`/`.url()`, `validator.js`, `email-validator`, `libphonenumber`) with max
  lengths; anchored regexes (`^...$`) only for simple, known formats.

## Canonicalize and allow-list (VAL-CANON-001, VAL-ALLOW-001)

Decode once, normalize Unicode (NFKC) and case-fold identifiers (emails, usernames) before validating and before
uniqueness checks. Prefer allow-lists (`^[a-z0-9_-]{3,32}$`, enum of sort fields) over deny-lists of "bad" strings,
which always miss a variant.

## Client vs server (VAL-SERVER-001)

HTML `required`/`pattern`/`maxlength` and front-end form libraries are for usability. Every rule must also exist on
the server; test by sending requests directly (curl, API client), not through the UI.
