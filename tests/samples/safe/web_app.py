import ast
import html
import os
import re
import shlex
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, redirect, render_template, request, send_file

app = Flask(__name__)

ALLOWED_UNITS = {"nginx", "postgres", "redis"}
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
ALLOWED_PATHS = {"/home", "/profile"}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", "--", host]).decode()


@app.route("/service")
def service_status():
    unit = request.args.get("unit")
    if unit not in ALLOWED_UNITS:
        return "unknown unit", 400
    return subprocess.check_output(["systemctl", "status", unit]).decode()


@app.route("/quoted")
def quoted():
    unit = request.args.get("unit")
    return subprocess.check_output("systemctl status " + shlex.quote(unit), shell=True).decode()


@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cursor.fetchall())


@app.route("/user")
def user():
    from safe_query import find_user

    connection = sqlite3.connect("app.db")
    return str(find_user(connection.cursor(), request.args.get("name")))


@app.route("/page")
def page():
    title = request.args.get("title")
    return render_template("page.html", title=title)


@app.route("/compute")
def compute():
    return str(ast.literal_eval("[1, 2, 3]"))


@app.route("/repeat")
def repeat():
    count = int(request.args.get("count"))
    return "x" * count


@app.route("/config", methods=["POST"])
def parse_config():
    return str(yaml.safe_load(request.get_data()))


@app.route("/escape")
def escape():
    comment = request.args.get("comment")
    return html.escape(comment)


@app.route("/download")
def download():
    filename = os.path.basename(request.args.get("file", ""))
    return send_file(os.path.join("/var/data", filename))


@app.route("/fetch")
def fetch():
    host = urlparse(request.args.get("url", "")).hostname or ""
    if host not in ALLOWED_HOSTS:
        abort(400)
    return requests.get("https://" + host).text


@app.route("/go")
def go():
    target = request.args.get("next", "/home")
    if target not in ALLOWED_PATHS:
        target = "/home"
    return redirect(target)


@app.route("/trace")
def trace():
    trace_id = request.args.get("trace", "")
    if not re.fullmatch(r"[A-Za-z0-9-]+", trace_id):
        abort(400)
    response = app.make_response("ok")
    response.headers["X-Trace-Id"] = trace_id
    return response
