# -*- coding: utf-8 -*-
"""
降噪验证样本：这个文件里写的都是「看起来像有问题、实际是安全写法」的代码。

它用于验证引擎的误报控制能力 —— 对这个文件的扫描结果应当是 0 命中。
如果它命中了，说明规则或降噪逻辑需要调整。
"""
import os

import yaml
from flask import Flask, request

app = Flask(__name__)

# 环境变量 / 配置中心读取，不是硬编码
DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ.get("API_KEY", "")
JWT_SECRET = "${JWT_SECRET}"

# 明显的占位符
PLACEHOLDER_PASSWORD = "your_password_here"
EXAMPLE_TOKEN = "changeme"


def get_db():
    import sqlite3
    return sqlite3.connect("app.db")


def load_config(path):
    """safe_load 不会执行任意构造器。"""
    with open(path, encoding="utf-8") as fp:
        return yaml.safe_load(fp.read())


def get_user(uid):
    """参数化查询，不是拼接。"""
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return cur.fetchone()


@app.route("/api/user")
def user():
    uid = request.args.get("id")
    return {"user": get_user(uid)}
