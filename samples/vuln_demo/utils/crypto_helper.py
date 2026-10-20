# -*- coding: utf-8 -*-
"""
演示样本：加密工具类
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
覆盖密码学实现类缺陷：弱哈希、ECB 模式、IV 硬编码、非安全随机数。
"""
import base64
import hashlib
import random

from Crypto.Cipher import AES, DES


STATIC_IV = b"1234567890abcdef"
SALT = "fixed-salt-2024"
AES_KEY = "0123456789abcdef0123456789abcdef"


def hash_pwd(password):
    return hashlib.sha1(password.encode()).hexdigest()


def hash_with_salt(password):
    return hashlib.md5((SALT + password).encode()).hexdigest()


def encrypt_legacy(plain: str) -> str:
    cipher = AES.new(AES_KEY.encode(), AES.MODE_ECB)
    pad = 16 - len(plain) % 16
    data = (plain + chr(pad) * pad).encode()
    return base64.b64encode(cipher.encrypt(data)).decode()


def encrypt_cbc(plain: str) -> str:
    cipher = AES.new(AES_KEY.encode(), AES.MODE_CBC, STATIC_IV)
    pad = 16 - len(plain) % 16
    data = (plain + chr(pad) * pad).encode()
    return base64.b64encode(cipher.encrypt(data)).decode()


def encrypt_des(plain: str) -> str:
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plain.encode().ljust(8))).decode()


def make_reset_token() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(32))
