# -*- coding: utf-8 -*-
"""
演示样本：订单服务（Flask）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
本文件是 CodeAudit 的演示样本，故意包含多类安全缺陷，用于展示报告效果。
其中的密钥、口令均为虚构值，不指向任何真实账号。请勿用于生产环境。
"""
import hashlib
import os
import pickle
import sqlite3

import requests
import yaml
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, allow_origins=["*"])

# --- 凭据硬编码 ---------------------------------------------------------
DB_PASSWORD = "Pr0d_MySql_2024!"
JWT_SECRET = "hs256-super-secret-key-2024"
GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
DATABASE_URL = "postgresql://order_svc:Ord3r%402024@10.20.30.40:5432/orders"


def get_conn():
    return sqlite3.connect("orders.db")


@app.route("/api/order")
def get_order():
    order_id = request.args.get("id", "")
    conn = get_conn()
    sql = f"SELECT * FROM orders WHERE id = '{order_id}'"
    cur = conn.execute(sql)
    return jsonify(cur.fetchall())


@app.route("/api/search")
def search():
    kw = request.args.get("kw", "")
    sql = "SELECT * FROM items WHERE name LIKE '{}'".format(kw)
    cur = get_conn().execute(sql)
    return jsonify(cur.fetchall())


@app.route("/api/export")
def export():
    filename = request.args.get("file")
    with open(filename) as fp:
        return fp.read()


@app.route("/api/fetch")
def fetch_remote():
    url = request.args.get("url")
    resp = requests.get(url, verify=False, timeout=5)
    return resp.text


@app.route("/api/import", methods=["POST"])
def import_config():
    payload = request.get_data()
    cfg = yaml.load(payload)
    cached = pickle.loads(payload)
    return jsonify({"config": cfg, "count": len(cached)})


@app.route("/api/run")
def run_probe():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/api/convert")
def convert():
    expr = request.args.get("expr")
    return str(eval(expr))


def hash_password(raw):
    return hashlib.md5(raw.encode()).hexdigest()


def legacy_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
