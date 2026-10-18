"""sk-grpc rules: insecure transport, missing interceptors, reflection, message limits, deadlines, error leaks."""

SKILL = "sk-grpc"

RULES = [
    {
        "id": "grpc-insecure-credentials", "check_id": "GRPC-TLS-001", "title": "gRPC channel or server without TLS", "files": ["code"],
        "pattern": r"grpc\.insecure_channel\(|grpc\.aio\.insecure_channel\(|credentials\.createInsecure\(\)|ServerCredentials\.createInsecure\(\)|insecure\.NewCredentials\(\)|grpc\.WithInsecure\(\)|\.usePlaintext\(\)|ChannelCredentials\.Insecure|add_insecure_port\(|InsecureChannelCredentials\(\)|InsecureServerCredentials\(\)|Channel::from_static\(\s*\"http://",
        "path_excludes": r"(?i)(test|spec|example|sample|local)", "confidence": "MEDIUM",
        "note": "Fine on localhost or inside a service mesh that enforces mTLS; confirm how the service is deployed.",
        "examples": {"match": ["conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))", "channel = grpc.insecure_channel('billing.internal:50051')"],
                     "no_match": ["conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))"]},
    },
    {
        "id": "grpc-server-no-interceptor", "check_id": "GRPC-AUTH-001", "type": "absence", "scope": "file",
        "title": "gRPC server created without auth interceptors or middleware", "files": ["code"],
        "when": r"grpc\.NewServer\(|grpc\.server\(|grpc\.aio\.server\(|new\s+grpc\.Server\(|ServerBuilder\.forPort\(|NettyServerBuilder|AddGrpc\(|Server::builder\(\)",
        "missing": r"(?i)(interceptor|UnaryInterceptor|StreamInterceptor|ChainUnaryInterceptor|intercept|auth|middleware|\[Authorize\]|RequireAuthorization|ServerInterceptors)",
        "confidence": "MEDIUM",
        "examples": {"match": ["s := grpc.NewServer()\npb.RegisterBillingServer(s, &server{})"], "no_match": ["s := grpc.NewServer(grpc.ChainUnaryInterceptor(authInterceptor))\npb.RegisterBillingServer(s, &server{})"]},
    },
    {
        "id": "grpc-reflection-enabled", "check_id": "GRPC-REFLECT-001", "title": "gRPC server reflection registered", "files": ["code"],
        "pattern": r"reflection\.Register\(|grpc_reflection\.v1alpha\.reflection|reflection\.enable_server_reflection\(|AddGrpcReflection\(|MapGrpcReflectionService\(|ProtoReflectionService\.newInstance\(|tonic_reflection|new\s+ReflectionService\(",
        "not_near": {"pattern": r"(?i)(isDev|IsDevelopment|DEBUG|development|ENABLE_REFLECTION|if\s+\w*dev)", "lines": 3}, "confidence": "LOW",
        "examples": {"match": ["reflection.Register(s)"], "no_match": ["if cfg.EnableReflection { reflection.Register(s) } // development only"]},
    },
    {
        "id": "grpc-huge-message-limit", "check_id": "GRPC-LIMIT-001", "title": "Very large or unlimited gRPC message size", "files": ["code", "config"],
        "pattern": r"(MaxRecvMsgSize|MaxCallRecvMsgSize|max_receive_message_length|maxInboundMessageSize|MaxReceiveMessageSize|maxReceiveMessageLength)['\"]?\s*[\(:=,]\s*[^\n]*?(-1\b|\d{9,}|math\.MaxInt\d*|Integer\.MAX_VALUE|null\b|1024\s*\*\s*1024\s*\*\s*\d{3,})",
        "confidence": "MEDIUM",
        "examples": {"match": ["s := grpc.NewServer(grpc.MaxRecvMsgSize(math.MaxInt32))", "options=[('grpc.max_receive_message_length', -1)]"],
                     "no_match": ["s := grpc.NewServer(grpc.MaxRecvMsgSize(4 << 20))"]},
    },
    {
        "id": "grpc-call-without-deadline", "check_id": "GRPC-LIMIT-001", "title": "gRPC client call without a deadline", "files": ["go", "py"],
        "pattern": r"\b\w*[Cc]lient\.\w+\(\s*context\.(Background|TODO)\(\)\s*,|\bstub\.\w+\((?![^)\n]*\btimeout\s*=)[^)\n]*\)",
        "confidence": "LOW", "note": "Without a deadline a slow dependency holds goroutines/threads indefinitely.",
        "examples": {"match": ["resp, err := billingClient.Charge(context.Background(), req)", "reply = stub.Charge(req)"],
                     "no_match": ["ctx, cancel := context.WithTimeout(ctx, 2*time.Second)\nresp, err := billingClient.Charge(ctx, req)", "reply = stub.Charge(req, timeout=2)"]},
    },
    {
        "id": "grpc-error-detail-leak", "check_id": "GRPC-ERROR-001", "title": "Internal error text returned in a gRPC status", "files": ["code"],
        "pattern": r"status\.Error\(\s*codes\.\w+\s*,\s*err\.Error\(\)\s*\)|status\.Errorf\(\s*codes\.\w+\s*,[^)]*%[vs][^)]*,\s*err\s*\)|context\.abort\(\s*grpc\.StatusCode\.\w+\s*,\s*(str\(e|repr\(e|traceback)|new\s+RpcException\([^)]*(ex|e)\.(Message|ToString\(\)|StackTrace)|Status\.\w+\.withDescription\(\s*e\.(getMessage|toString)\(\)|callback\(\s*\{\s*code[^}]*message\s*:\s*(err|e)\.(message|stack)",
        "confidence": "LOW",
        "examples": {"match": ["return nil, status.Error(codes.Internal, err.Error())"], "no_match": ["log.Error(err)\nreturn nil, status.Error(codes.Internal, \"internal error\")"]},
    },
    {
        "id": "grpc-proto-no-validation", "check_id": "GRPC-INPUT-001", "type": "absence", "scope": "project",
        "title": "Proto request messages with no validation rules or validator anywhere", "files": [".proto", "code"],
        "when": r"(?m)^\s*message\s+\w+Request\s*\{",
        "missing": r"validate\.rules|buf\.validate|\(validate\.|protovalidate|protoc-gen-validate|\.Validate\(\)|ValidateAll\(\)",
        "confidence": "LOW",
        "examples": {"match": ["syntax = \"proto3\";\nmessage ChargeRequest {\n  string account_id = 1;\n  int64 amount = 2;\n}"],
                     "no_match": ["import \"buf/validate/validate.proto\";\nmessage ChargeRequest {\n  int64 amount = 2 [(buf.validate.field).int64.gt = 0];\n}"]},
    },
    {
        "id": "grpc-web-any-origin", "check_id": "GRPC-GATEWAY-001", "title": "grpc-web/gateway accepts any origin", "files": ["code"],
        "pattern": r"WithOriginFunc\(\s*func\([^)]*\)\s*bool\s*\{\s*return\s+true|WithAllowedRequestHeaders\(\s*\[\]string\{\s*\"\*\"\s*\}|AllowAnyOrigin\(\)[^\n]*(Grpc|grpc)|EnableGrpcWeb\([^)]*\)[^\n]*AllowAnyOrigin",
        "confidence": "MEDIUM",
        "examples": {"match": ["wrapped := grpcweb.WrapServer(s, grpcweb.WithOriginFunc(func(origin string) bool { return true }))"],
                     "no_match": ["wrapped := grpcweb.WrapServer(s, grpcweb.WithOriginFunc(func(o string) bool { return o == \"https://app.acme.com\" }))"]},
    },
]
