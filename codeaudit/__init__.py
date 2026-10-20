# -*- coding: utf-8 -*-
"""CodeAudit —— AI 辅助代码安全体检引擎（零依赖）。"""

from .engine import (  # noqa: F401
    AuditResult,
    Finding,
    SEVERITY_LABEL,
    SEVERITY_ORDER,
    load_rules,
    scan,
)

__version__ = "1.0.0"
__all__ = ["AuditResult", "Finding", "scan", "load_rules",
           "SEVERITY_ORDER", "SEVERITY_LABEL", "__version__"]
