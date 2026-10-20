# -*- coding: utf-8 -*-
"""
演示样本：AI 客服 Agent
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
本文件是 CodeAudit 的演示样本，覆盖「大模型应用特有风险」类别：
Prompt 拼接、模型输出直接执行、Key 硬编码、Agent 工具缺少权限校验。
密钥为虚构值。
"""
import os
import sqlite3
import subprocess

import requests
from openai import OpenAI

LLM_API_KEY = "sk-proj-3Hd8Ae5Uc0JgQk7Zx2Nm4Pv9Rt1Lb6Wy3Hd8Ae5Uc"
client = OpenAI(api_key=LLM_API_KEY, base_url="https://api.example-llm.com/v1")

SYSTEM_PROMPT = "你是电商客服助手，可以查询订单、发起退款、修改收货地址。"


def answer(user_question, history):
    """把用户问题直接拼进提示词——可被提示注入改写指令。"""
    prompt = f"{SYSTEM_PROMPT}\n用户问题：{user_question}\n请回答："
    messages = history + [{"role": "user", "content": prompt}]
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages)
    return resp.choices[0].message.content


def run_agent_loop(user_question):
    """把模型输出当命令执行——模型被诱导即可造成 RCE。"""
    reply = answer(user_question, [])
    if reply.startswith("QUERY:"):
        sql = reply[6:].strip()
        conn = sqlite3.connect("shop.db")
        return conn.execute(sql).fetchall()
    if reply.startswith("RUN:"):
        cmd = reply[4:].strip()
        return subprocess.run("bash -c '" + cmd + "'", shell=True, capture_output=True)
    if reply.startswith("EVAL:"):
        return eval(reply[5:].strip())
    return reply


def fetch_knowledge(url):
    """RAG 文档抓取：目标地址来自外部。"""
    r = requests.get(url, timeout=10)
    return r.text[:4000]


def retrieve_context(query_text):
    ctx = fetch_knowledge(os.environ.get("KB_ENDPOINT"))
    return f"参考资料：{ctx}\n问题：{query_text}"


TOOLS = [
    {"name": "query_order", "description": "查询订单状态", "danger": "read"},
    {"name": "refund", "description": "发起退款", "danger": "write"},
    {"name": "update_address", "description": "修改收货地址", "danger": "write"},
    {"name": "delete_account", "description": "注销用户账号", "danger": "destroy"},
]
