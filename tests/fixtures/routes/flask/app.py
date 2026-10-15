from flask import Flask, Blueprint
from flask_login import login_required
app = Flask(__name__)
admin = Blueprint("admin", __name__, url_prefix="/ignored")

@app.route("/")
def index():
    return "hi"

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    return "me"

@admin.get("/users")
def admin_users():
    return []

app.register_blueprint(admin, url_prefix="/admin")
