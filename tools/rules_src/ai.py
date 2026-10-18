"""sk-ai rules (umbrella LLM application audit; prompt injection, agents and RAG have their own skills)."""

SKILL = "sk-ai"

MACROS = {
    "AI_PROVIDER": r"(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE_AI|GROQ|MISTRAL|COHERE|HUGGING_?FACE|HF|REPLICATE|TOGETHER|PERPLEXITY|DEEPSEEK|XAI|GROK|OPENROUTER|FIREWORKS|AZURE_OPENAI|LLM|AI)",
    "PUBLIC_PREFIX": r"(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC|STORYBOOK|VUE_APP)",
    "SCHEMA_VALIDATE": r"(safeParse|z\.object|zod|Schema\b|schema\.|pydantic|BaseModel|model_validate|parse_obj|TypeAdapter|jsonschema|[Aa]jv|validate\(|response_format|json_schema|generateObject|with_structured_output|instructor)",
    "LLM_ISH": r"(?i:openai|anthropic|llm|completion|chat|assistant|gemini|ollama|bedrock|langchain|prompt)",
}

RULES = [
    # ------------------------------------------------------------------ KEY
    {
        "id": "ai-browser-client", "check_id": "AI-KEY-001", "title": "LLM SDK allowed to run in the browser (API key shipped to clients)",
        "files": ["js", "web"], "pattern": r"dangerouslyAllowBrowser\s*:\s*true", "confidence": "HIGH",
        "note": "Anyone can read the key from the bundle and spend on your account. Call the model from your server.",
        "examples": {"match": ["const client = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true });"],
                     "no_match": ["const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });"]},
    },
    {
        "id": "ai-public-env-key", "check_id": "AI-KEY-001", "title": "Model provider key in a client-exposed environment variable",
        "files": ["code", "web", "env", "config"],
        "pattern": r"\b{{PUBLIC_PREFIX}}_\w*{{AI_PROVIDER}}\w*(KEY|TOKEN|SECRET)\b", "confidence": "HIGH",
        "note": "Variables with these prefixes are inlined into the client bundle by the build tool.",
        "examples": {"match": ["const ai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY });", "VITE_ANTHROPIC_API_KEY=placeholder"],
                     "no_match": ["const ai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });", "NEXT_PUBLIC_APP_NAME=demo"]},
    },
    {
        "id": "ai-provider-called-from-client", "check_id": "AI-KEY-001", "title": "Browser code calls a model provider API directly",
        "files": ["js", "web"],
        "pattern": r"['\"`]https://(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai|openrouter\.ai/api|api\.together\.xyz|api\.cohere\.(ai|com)|api\.deepseek\.com)",
        "file_requires": r"(['\"]use client['\"]|\buseState\(|\buseEffect\(|\bdocument\.|\bwindow\.|onClick|addEventListener)", "confidence": "MEDIUM",
        "examples": {"match": ["'use client';\nconst r = await fetch('https://api.openai.com/v1/chat/completions', { headers: { Authorization: 'Bearer ' + key } });"],
                     "no_match": ["const r = await fetch('/api/chat', { method: 'POST', body });"]},
    },
    # ------------------------------------------------------------------ COST
    {
        "id": "ai-params-from-request", "check_id": "AI-COST-001", "title": "Model, token limit or sample count taken from the request",
        "files": ["code"],
        "pattern": r"\b(model|max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_completion_tokens|max_new_tokens|n|num_ctx|reasoning_effort)\b\s*[:=]\s*({{SRC}})",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 15}, "confidence": "MEDIUM",
        "note": "Callers can pick the most expensive model and the largest output. Map an allow-listed choice server-side.",
        "examples": {"match": ["const r = await openai.chat.completions.create({\n  model: req.body.model,\n  messages,\n});",
                               "resp = client.messages.create(max_tokens=request.json['max_tokens'], model=MODEL, messages=msgs)"],
                     "no_match": ["const r = await openai.chat.completions.create({\n  model: MODELS[plan] ?? 'small',\n  max_tokens: 800,\n  messages,\n});"]},
    },
    {
        "id": "ai-no-output-limit", "check_id": "AI-COST-001", "type": "absence", "scope": "file",
        "title": "Model call without an output token limit", "files": ["code"],
        "when": r"chat\.completions\.create|messages\.create\(|responses\.create\(|\bgenerateText\(|\bstreamText\(|generate_content\(|\bcompletion\(|\bacompletion\(|ollama\.(chat|generate)\(",
        "missing": r"max_tokens|maxTokens|max_output_tokens|maxOutputTokens|max_new_tokens|max_completion_tokens|maxCompletionTokens|num_predict|maxOutputTokens",
        "confidence": "LOW",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages });"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, messages, max_tokens: 800 });"]},
    },
    {
        "id": "ai-no-rate-limit", "check_id": "AI-COST-001", "type": "absence", "scope": "project",
        "title": "Request-driven model calls but no rate limiting anywhere in the project", "files": ["code"],
        "when": "{{LLM_CALL}}", "file_requires": "{{SRC}}", "missing": "{{RATE_LIMIT}}|(?i:quota|usage_?limit|credits?_?(left|remaining)|tokens?_?used)",
        "confidence": "MEDIUM",
        "note": "Without per-user limits one account (or a stolen session) can run up the provider bill and exhaust shared quota.",
        "examples": {"match": ["app.post('/chat', async (req, res) => {\n  const r = await openai.chat.completions.create({ model: 'm', max_tokens: 500, messages: [{ role: 'user', content: req.body.q }] });"],
                     "no_match": ["app.post('/chat', rateLimit({ windowMs: 60000, max: 20 }), async (req, res) => {\n  const r = await openai.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: req.body.q }] });"]},
    },
    # ------------------------------------------------------------------ OUT
    {
        "id": "ai-output-to-html", "check_id": "AI-OUT-001", "title": "Model output inserted as raw HTML", "files": ["js", "web", "py", "rb", "php"],
        "pattern": r"(innerHTML\s*\+?=|outerHTML\s*=|insertAdjacentHTML\([^,\n]*,|document\.write\(|dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:|v-html\s*=\s*['\"]|\{@html\s|\.html\(|mark_safe\(|Markup\(|\|\s*safe\b|html_safe|raw\()\s*[^;\n]*{{MODEL_OUT}}",
        "file_requires": "{{LLM_ISH}}", "not_near": {"pattern": r"(?i)(DOMPurify|sanitize|bleach|nh3|escape)", "lines": 3}, "confidence": "MEDIUM",
        "note": "A prompt-injected answer becomes stored/reflected XSS. Render as text, or sanitize Markdown/HTML output.",
        "examples": {"match": ["// chat widget\nbubble.innerHTML = completion.choices[0].message.content;",
                               "// assistant\n<div dangerouslySetInnerHTML={{ __html: answer }} />"],
                     "no_match": ["// chat widget\nbubble.textContent = completion.choices[0].message.content;",
                                  "// chat\nbubble.innerHTML = DOMPurify.sanitize(marked.parse(answer));"]},
    },
    {
        "id": "ai-output-to-sql", "check_id": "AI-OUT-001", "title": "Model output executed as SQL (text-to-SQL)", "files": ["code"],
        "pattern": r"\.(execute|executescript|query|raw|exec|executeQuery|executeUpdate|\$queryRawUnsafe|\$executeRawUnsafe|sql)\(\s*(sql\w*|query\w*|stmt|statement|{{MODEL_OUT}})[\w.\[\]'\"]*\s*[,)]",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 25}, "confidence": "MEDIUM",
        "note": "Generated SQL runs with the app's DB rights. Use a read-only role, an allow-list of tables/statements, row limits and a parser check, or generate parameters for fixed queries instead.",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages });\nconst sql = r.choices[0].message.content;\nconst rows = await db.query(sql);",
                               "resp = llm.invoke(prompt)\ncursor.execute(resp.content)"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, messages });\nconst rows = await db.query('SELECT * FROM faq WHERE id = $1', [id]);"]},
    },
    {
        "id": "ai-output-to-exec", "check_id": "AI-OUT-001", "title": "Model output passed to eval / shell / process execution", "files": ["code"],
        "pattern": r"(\beval|\bexec|new Function|\bexecSync|\bexecFile\w*|\bspawn\w*|subprocess\.\w+|os\.system|os\.popen|vm\.runIn\w+|Runtime\.getRuntime\(\)\.exec|exec\.Command|shell_exec|system|passthru)\s*\(\s*[^)\n]*{{MODEL_OUT}}",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 25}, "confidence": "MEDIUM",
        "note": "Prompt injection becomes remote code execution. Run generated code only in a disposable sandbox without secrets or network, after human review.",
        "examples": {"match": ["resp = client.messages.create(model=M, max_tokens=500, messages=msgs)\nsubprocess.run(resp.content[0].text, shell=True)",
                               "const out = await generateText({ model, prompt });\neval(out.text);"],
                     "no_match": ["const out = await generateText({ model, prompt });\nconsole.log(out.text);"]},
    },
    {
        "id": "ai-output-json-unvalidated", "check_id": "AI-OUT-002", "title": "Model output parsed as JSON and used without schema validation", "files": ["code"],
        "pattern": r"(JSON\.parse|json\.loads|json\.Unmarshal|JsonSerializer\.Deserialize\w*|objectMapper\.readValue|json_decode)\(\s*[^)\n]*{{MODEL_OUT}}",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 20}, "not_near": {"pattern": "{{SCHEMA_VALIDATE}}", "lines": 6}, "confidence": "LOW",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages });\nconst action = JSON.parse(r.choices[0].message.content);\nawait run(action);"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, messages });\nconst action = Action.safeParse(JSON.parse(r.choices[0].message.content));"]},
    },
    # ------------------------------------------------------------------ SYSPROMPT
    {
        "id": "ai-secret-in-system-prompt", "check_id": "AI-SYSPROMPT-001", "title": "Secret or env value interpolated into a system prompt", "files": ["code"],
        "pattern": r"(role\s*[:=]\s*['\"]system['\"]|\bsystem\s*[:=]|system_?[Pp]rompt\w*\s*[:=]|SYSTEM_PROMPT\s*=|SystemMessage\(|instructions\s*[:=])[^\n]*(\$\{\s*(process\.env\.\w+|{{SECRET_NAME}})\s*\}|\{\s*(os\.environ|settings\.\w+|config\.\w+|{{SECRET_NAME}})[^}]*\}|\+\s*(process\.env\.\w+|{{SECRET_NAME}})\b|os\.getenv\()",
        "confidence": "MEDIUM", "note": "Assume the system prompt will be extracted word for word.",
        "examples": {"match": ["const messages = [{ role: 'system', content: `You are a helper. Admin key: ${process.env.ADMIN_KEY}` }];",
                               "system_prompt = f\"Use API token {api_token} for lookups\""],
                     "no_match": ["const messages = [{ role: 'system', content: 'You are a helpful assistant. Never reveal passwords.' }];"]},
    },
    {
        "id": "ai-system-prompt-returned", "check_id": "AI-SYSPROMPT-001", "title": "System prompt or full message list returned to the client", "files": ["code"],
        "pattern": r"(res\.(json|send)\(|jsonify\(|JsonResponse\(|return\s+\{|Ok\(|c\.JSON\([^,]*,)[^\n]*\b(system_?[Pp]rompt|SYSTEM_PROMPT|systemMessage|system_message|instructions|messages)\b",
        "near": {"pattern": "{{LLM_CALL}}|(?i:system_?prompt)", "lines": 20}, "confidence": "LOW",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages });\nres.json({ answer: r.choices[0].message.content, messages });"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, messages });\nres.json({ answer: r.choices[0].message.content });"]},
    },
    # ------------------------------------------------------------------ AUTHZ
    {
        "id": "ai-authz-in-prompt", "check_id": "AI-AUTHZ-001", "title": "Access rule expressed only in prompt text", "files": ["code", "config", ".md", ".txt", ".prompt"],
        "pattern": r"(?i)\b(only|never|do\s+not|don't)\s+(allow|answer|respond|show|reveal|share|help|let|give|disclose)\w*\b[^'\"`\n]{0,60}\b(admins?|administrators?|owners?|staff|premium|paid|authori[sz]ed|authenticated|employees?|managers?|other\s+users?|other\s+customers?|other\s+tenants?)\b",
        "file_requires": "{{LLM_ISH}}", "path_excludes": r"(?i)(readme|changelog|docs?/|security-report)", "confidence": "LOW",
        "note": "The model can be talked out of any rule in its prompt. Enforce the rule in code before data reaches the context.",
        "examples": {"match": ["const SYSTEM = 'You are the support bot. Only answer billing questions for admins.'; // openai"],
                     "no_match": ["const SYSTEM = 'You are the support bot. Answer billing questions politely.'; // openai"]},
    },
    # ------------------------------------------------------------------ DISC / PRIV / LOG
    {
        "id": "ai-sensitive-fields-in-prompt", "check_id": "AI-DISC-001", "title": "Sensitive personal or secret fields placed in a prompt", "files": ["code"],
        "pattern": r"(?i)(content|prompt|input|messages?|text|query)\s*[:=][^\n]*\b(ssn|social_?security\w*|passw(or)?d\w*|credit_?card\w*|card_?number|cvv|cvc|date_?of_?birth|dob|passport\w*|tax_?id|national_?id|iban|account_?number|diagnosis|medical_?\w*|api_?key|access_?token)\b",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 15}, "confidence": "MEDIUM",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, max_tokens: 300,\n  messages: [{ role: 'user', content: `Assess risk for ${user.name}, SSN ${user.ssn}` }] });"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, max_tokens: 300,\n  messages: [{ role: 'user', content: `Summarize ticket ${ticket.subject}` }] });"]},
    },
    {
        "id": "ai-whole-record-in-prompt", "check_id": "AI-DISC-001", "title": "Whole user/customer record serialized into a prompt", "files": ["code"],
        "pattern": r"(JSON\.stringify|json\.dumps|to_json|json\.Marshal|JsonSerializer\.Serialize|model_dump_json|\.dict)\(\s*(user|users|customer|customers|patient|patients|account|accounts|profile|member|employee|order|orders|row|rows|record|records)s?\b\s*[,)]",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 12}, "confidence": "LOW",
        "note": "Send only the fields the task needs; mask identifiers and contact data.",
        "examples": {"match": ["const prompt = `Write a renewal email for this customer: ${JSON.stringify(customer)}`;\nconst r = await generateText({ model, prompt, maxTokens: 400 });"],
                     "no_match": ["const prompt = `Write a renewal email for ${customer.firstName} on plan ${customer.plan}`;\nconst r = await generateText({ model, prompt, maxTokens: 400 });"]},
    },
    {
        "id": "ai-provider-storage-on", "check_id": "AI-PRIV-001", "title": "Provider-side storage of completions explicitly enabled", "files": ["code"],
        "pattern": r"\bstore\s*[:=]\s*(true|True)\b", "near": {"pattern": "{{LLM_CALL}}", "lines": 10}, "confidence": "LOW",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages, store: true });"],
                     "no_match": ["const r = await openai.chat.completions.create({ model, messages, store: false });"]},
    },
    {
        "id": "ai-prompt-logged", "check_id": "AI-LOG-001", "title": "Prompts or completions written to application logs", "files": ["code"],
        "pattern": r"{{LOG_CALL}}[^\n]*\b(prompt|messages|completion|system_?[Pp]rompt|choices|chat_?history|conversation)\b",
        "near": {"pattern": "{{LLM_CALL}}", "lines": 15}, "confidence": "LOW",
        "examples": {"match": ["logger.info(f\"prompt={prompt}\")\nresp = client.messages.create(model=M, max_tokens=400, messages=msgs)"],
                     "no_match": ["logger.info(\"chat request\", extra={\"user\": uid, \"tokens\": n})\nresp = client.messages.create(model=M, max_tokens=400, messages=msgs)"]},
    },
    {
        "id": "ai-tracing-enabled", "check_id": "AI-LOG-001", "title": "LLM tracing/observability captures full prompts (check redaction and access)", "files": ["code", "env", "config"],
        "pattern": r"(LANGCHAIN_TRACING_V2|LANGSMITH_TRACING)\s*[=:]\s*['\"]?true|\bLangfuse\(|langfuse\.(trace|observe)|@observe\b|helicone\.ai|\bweave\.init\(|traceloop\.init|Traceloop\.init",
        "not_near": {"pattern": r"(?i)(mask|redact|hide_?inputs|hideInputs|hide_?outputs|anonymi[sz])", "lines": 6}, "confidence": "LOW",
        "examples": {"match": ["LANGCHAIN_TRACING_V2=true", "langfuse = Langfuse()"],
                     "no_match": ["langfuse = Langfuse(mask=redact_pii)"]},
    },
    # ------------------------------------------------------------------ SUPPLY / POISON
    {
        "id": "ai-trust-remote-code", "check_id": "AI-SUPPLY-001", "title": "trust_remote_code enabled (runs code from the model repository)",
        "files": ["py", "config", ".ipynb"], "pattern": r"trust_remote_code\s*[=:]\s*(True|true)", "confidence": "HIGH",
        "examples": {"match": ["model = AutoModel.from_pretrained(name, trust_remote_code=True)"], "no_match": ["model = AutoModel.from_pretrained(name, revision=REV)"]},
    },
    {
        "id": "ai-unsafe-weights-load", "check_id": "AI-SUPPLY-001", "title": "Model weights loaded with pickle (torch.load without weights_only)",
        "files": ["py", ".ipynb"], "pattern": r"torch\.load\((?![^)\n]*weights_only\s*=\s*True)|\bload_model\([^)\n]*\.(pkl|pickle|pt|pth|bin)['\"]|(joblib|pickle|dill|cloudpickle)\.load\([^)\n]*(model|\.pkl|\.joblib)",
        "confidence": "MEDIUM", "note": "Prefer safetensors; torch.load(..., weights_only=True).",
        "examples": {"match": ["state = torch.load(path)", "clf = joblib.load('model.joblib')"],
                     "no_match": ["state = torch.load(path, weights_only=True)", "from safetensors.torch import load_file"]},
    },
    {
        "id": "ai-model-unpinned", "check_id": "AI-SUPPLY-001", "title": "Hub model/dataset downloaded without a pinned revision",
        "files": ["py", ".ipynb"],
        "pattern": r"\.from_pretrained\(\s*['\"][\w.-]+/[\w.-]+['\"](?![^)\n]*revision\s*=)|\b(hf_hub_download|snapshot_download|load_dataset)\(\s*(repo_id\s*=\s*)?['\"][\w.-]+/[\w.-]+['\"](?![^)\n]*revision\s*=)|\bpipeline\([^)\n]*model\s*=\s*['\"][\w.-]+/[\w.-]+['\"](?![^)\n]*revision\s*=)",
        "confidence": "LOW", "note": "A compromised or changed upstream repo silently changes the model you run. Pin a commit hash.",
        "examples": {"match": ["tok = AutoTokenizer.from_pretrained('org/model-7b')", "ds = load_dataset('org/data')"],
                     "no_match": ["tok = AutoTokenizer.from_pretrained('org/model-7b', revision='3f1c2a9')"]},
    },
    {
        "id": "ai-finetune-from-user-data", "check_id": "AI-POISON-001", "title": "Fine-tuning job built from user-generated data", "files": ["code"],
        "pattern": r"fine_tuning\.jobs\.create|fineTuning\.jobs\.create|FineTune\.create|create_fine_tuning_job|Trainer\(|SFTTrainer\(",
        "file_requires": r"(?i)(feedback|thumbs|user_?(messages|data|content)|conversations|chat_?logs|transcripts|ratings?)",
        "confidence": "LOW", "note": "Users who can write the training data can plant backdoors or bias. Review, filter and track provenance.",
        "examples": {"match": ["rows = load_feedback(conversations)\njob = client.fine_tuning.jobs.create(training_file=f.id, model=base)"],
                     "no_match": ["job = client.fine_tuning.jobs.create(training_file=CURATED_FILE_ID, model=base)"]},
    },
    # ------------------------------------------------------------------ TEST
    {
        "id": "ai-no-security-evals", "check_id": "AI-TEST-001", "type": "absence", "scope": "project",
        "title": "LLM features without any visible security evals", "files": ["code", "config"],
        "when": "{{LLM_CALL}}",
        "missing": r"(?i)(promptfoo|garak|deepeval|ragas|pyrit|giskard|llm[-_]guard|rebuff|lakera|prompt[-_ ]?injection|jailbreak|red[-_ ]?team)",
        "confidence": "LOW", "note": "Test folders are skipped by default; re-run with --include-tests before reporting this.",
        "examples": {"match": ["const r = await openai.chat.completions.create({ model, messages, max_tokens: 50 });"],
                     "no_match": ["// promptfoo config lives in promptfooconfig.yaml\nconst r = await openai.chat.completions.create({ model, messages, max_tokens: 50 });"]},
    },
]
