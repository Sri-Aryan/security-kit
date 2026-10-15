# Semgrep rule tests for skills/sk-api/rules/api.yml (Python).
import os, subprocess, traceback, requests, jwt
from flask import Flask, request, send_file
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

app = Flask(__name__)
api = FastAPI()

# ruleid: sk-flask-state-change-without-auth-decorator
@app.route("/orders", methods=["POST"])
def create_order():
    return "ok"

# ok: sk-flask-state-change-without-auth-decorator
@app.route("/orders", methods=["POST"])
@login_required
def create_order2():
    return "ok"

# ruleid: sk-flask-state-change-without-auth-decorator
@api.delete("/items/{item_id}")
def delete_item(item_id: int):
    return {}

# ok: sk-flask-state-change-without-auth-decorator
@api.delete("/items/{item_id}")
def delete_item2(item_id: int, user=Depends(get_current_user)):
    return {}

def who(token):
    # ruleid: sk-jwt-decode-without-verify-py
    return jwt.decode(token, options={"verify_signature": False})

def who2(token):
    # ruleid: sk-jwt-none-algorithm-py
    return jwt.decode(token, KEY, algorithms=["HS256", "none"])

def make_user():
    # ruleid: sk-mass-assignment-py
    return User(**request.json)

def search():
    q = request.args.get("q")
    # ruleid: sk-sql-injection-py, sk-sql-string-building
    cur.execute("SELECT * FROM products WHERE name = '%s'" % q)
    # ok: sk-sql-injection-py
    cur.execute("SELECT * FROM products WHERE name = %s", (q,))

def fstring_sql(name):
    # ruleid: sk-sql-string-building
    sql = f"SELECT * FROM users WHERE name = '{name}'"
    return sql

def run(host):
    # ruleid: sk-command-injection-py
    os.system("ping -c 1 " + host)
    # ok: sk-command-injection-py
    subprocess.run(["ping", "-c", "1", host])

def get_file():
    name = request.args["name"]
    # ruleid: sk-path-traversal-py
    return send_file(os.path.join("files", name))

def fetch():
    # ruleid: sk-ssrf-py
    return requests.get(request.args["url"]).text

@api.get("/preview")
def preview(url: str):
    # ruleid: sk-ssrf-py
    return requests.get(url).text

def handler():
    try:
        pass
    except Exception:
        # ruleid: sk-stack-trace-in-response-py
        return {"error": traceback.format_exc()}, 500

# ruleid: sk-cors-wildcard-credentials-py
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# ok: sk-cors-wildcard-credentials-py
api.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)

# ruleid: sk-debug-mode-py
app.run(host="0.0.0.0", debug=True)

# ruleid: sk-tls-verify-disabled
requests.get("https://internal", verify=False)

# ruleid: sk-hardcoded-secret-py
SECRET_KEY = "django-insecure-abc123def456"
# ruleid: sk-hardcoded-secret-py
JWT_KEY = os.environ.get("JWT_SECRET", "fallback-secret-123")
# ok: sk-hardcoded-secret-py
API_KEY = os.environ["API_KEY"]

# ruleid: sk-drf-serializer-all-fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"

# ok: sk-drf-serializer-all-fields
class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ["id", "total"]
