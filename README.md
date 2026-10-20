# CodeAudit

**AI 辅助代码安全体检引擎** —— 零依赖、可私有化部署、交付客户可直接阅读的中文报告。

```bash
python -m codeaudit demo                      # 用内置样本 30 秒看到完整报告效果
python -m codeaudit scan D:\your\project -o reports --title "某某科技 · 订单系统"
python -m codeaudit rules                     # 查看全部 60 条规则
```

---

## 为什么是这个方向

上一波「用 AI 批量挖漏洞刷赏金」的红利已经结束，原因是**发现被商品化了**：
agent 扫一遍就能出一堆告警，于是稀缺的不再是"发现问题"，而是"证明问题可利用"和"讲清业务影响"。

同时对中小企业来说，市面上并不缺免费扫描器，缺的是**一份能直接交给开发去改的清单**。
CodeAudit 就落在这个缺口上：

| | 免费扫描工具 | 赏金平台 | CodeAudit |
|---|---|---|---|
| 输出 | 告警列表 | 只有被认可的漏洞才给钱 | 带修复方案与验证步骤整改清单 |
| 误报 | 大量，需自己筛 | triage 排期不可控 | 三层降噪 + 人工复核 |
| AI 应用风险 | 基本不覆盖 | 视平台规则 | 独立规则组（Prompt 注入 / 模型输出执行 / Agent 越权 / MCP 配置） |
| 收入确定性 | 0 | 平台规则决定 | 按项目/订阅收费 |

---

## 实测数据

| 指标 | 结果 |
|---|---|
| 规则数量 | 60 条，覆盖 9 大类风险 |
| 演示样本（7 文件 / 341 行，故意满身是洞） | 63 处命中：严重 14 / 高危 31 / 中危 12 / 低危 6 |
| 干净样本（46 行，全部是安全写法） | **0 处命中**，同时自动过滤掉 2 处疑似误报 |
| 扫描速度 | 341 行耗时 0.02 秒 |

干净样本的 0 命中是刻意验证的：里面包含 `os.environ["DB_PASSWORD"]`、
`"${JWT_SECRET}"`、`yaml.safe_load`、参数化 SQL 这些「看起来像问题」的写法，
它们不应该产生任何告警。误报率是这类服务的生死线。

---

## 技术要点

**零第三方依赖。** 只用 Python 标准库，客户机器上有 Python 就能跑，
不需要 pip install、不需要联网、可以整包丢进内网。

**轻量污点追踪。** 这不是纯正则匹配器。引擎会先识别文件内所有
「从 request / req / query / params 取值后赋给普通变量」的变量名，
再把这些变量名并入危险汇聚点（SSRF、路径穿越）的匹配模式，实现单文件内的数据流追踪：

```python
url = request.args.get("url")        # 变量 url 被标记为污点
resp = requests.get(url)             # 命中 SSRF —— 跨行传递也能抓到
```

**三层降噪。** 安全报告最大的敌人是噪声，误报一多客户就不看了：

1. 占位符与环境变量识别 —— `your_password_here`、`${JWT_SECRET}`、`os.environ[...]` 一律不算问题；
2. 注释降噪 —— 注释里的中低危命中默认跳过，但 critical/high 保留（注释里的真实密钥仍然危险）；
3. 前端语义隔离 —— `.js/.ts` 在 `web/ static/ public/` 等目录下才被当作浏览器代码，
   避免把服务端持有密钥的正常写法报成"密钥泄露到前端"。

**报告即交付物。** 每条问题都带四样东西：文件行号、风险说明、修复建议、
以及「如何验证已修好」（可能是 `aws sts get-caller-identity` 这样的具体命令）。
报告中的密钥自动打码，可以直接转发给客户或同事。HTML 报告自包含、双击即开。

---

## 目录结构

```
codeaudit/
├── codeaudit/              引擎本体
│   ├── engine.py           扫描核心：文件遍历、规则匹配、污点追踪、降噪、评分
│   ├── report.py           报告生成：HTML（自包含）/ Markdown / JSON
│   ├── cli.py              命令行入口
│   └── rules.json          规则库（可热更新、可定制，不需要改代码）
├── samples/
│   ├── vuln_demo/          演示样本：故意包含 9 类缺陷的 Python / Node / 前端 / AI Agent 代码
│   └── clean_demo/         降噪验证样本：应当 0 命中
├── landing/index.html      服务落地页（单文件，可直接部署到任意静态托管）
├── docs/
│   ├── 01_报价与交付SOP.md  从客户问诊到复测结项的作业手册
│   └── 02_获客与话术.md     渠道优先级、内容选题、私信话术、异议处理
└── reports/                扫描输出目录
```

---

## 命令参考

```bash
# 预览：扫描内置演示样本
python -m codeaudit demo

# 正式扫描
python -m codeaudit scan <目录或文件> -o reports --title "客户名 · 系统名"

# 客户内网部署场景：只出 JSON，回传后由我们出报告
python -m codeaudit scan <目录> -f json -o /tmp/out

# 只输出给客户看的精简版
python -m codeaudit scan <目录> --min-severity high --name 客户名-精简版

# 接入 CI：发现问题返回非零退出码
python -m codeaudit scan . --fail-on high

# 查看规则覆盖范围
python -m codeaudit rules
```

常用参数：`--include-comments`（保留注释命中）、`--rules <path>`（指定自定义规则库）。

---

## 规则覆盖

| 类别 | 规则 | 典型问题 |
|---|---|---|
| 凭据泄露 | SEC101–115 | AWS / 阿里云 / 腾讯云 / GitHub / 支付平台密钥、私钥、数据库连接串、JWT 签名密钥 |
| 注入 | SEC201–209 | SQL 拼接、命令执行、动态 eval、SSTI、动态导入 |
| 反序列化 | SEC301–307 | pickle、yaml.load、Java ObjectInputStream、PHP unserialize、.NET BinaryFormatter |
| 文件与路径 | SEC401–404 | 路径穿越、Zip Slip、上传校验缺失、777 权限 |
| 网络与传输 | SEC501–503 | SSRF、TLS 校验关闭、全网卡监听 |
| 密码学 | SEC601–606 | MD5/SHA1 存口令、ECB 模式、DES/RC4、静态 IV、非安全随机数 |
| 配置 | SEC701–706 | debug=True、CORS 通配、CSRF 关闭、堆栈回显、浮动依赖版本 |
| 前端 | SEC801–805 | innerHTML、dangerouslySetInnerHTML、document.write、v-html |
| AI 应用 | SEC901–906 | 大模型 Key 泄露到前端、Prompt 拼接、模型输出被直接执行、Agent 工具越权、MCP 明文密钥、向量库裸暴露 |

**定制规则**：客户用的框架如果通用规则覆盖不到，往 `rules.json` 的 `rules` 数组追加即可，
示例如下（这类定制可以单独收费）：

```json
{
  "id": "CUS001",
  "title": "XX 框架的权限注解缺失",
  "severity": "high",
  "cwe": "CWE-862",
  "langs": ["java"],
  "pattern": "@RequestMapping[^\\n]{0,120}(?![^\\n]{0,200}@PreAuthorize)",
  "fix": "该接口缺少权限注解，请补充 @PreAuthorize 并核对角色表达式。",
  "tags": ["auth"]
}
```

---

## 商业落地

- 报价与交付流程见 [docs/01_报价与交付SOP.md](docs/01_报价与交付SOP.md)
- 获客渠道与话术见 [docs/02_获客与话术.md](docs/02_获客与话术.md)
- 落地页模板见 [landing/index.html](landing/index.html)

定价分四档：体验 ¥299 / 标准 ¥1,280 / 专业 ¥2,980 / 企业 ¥8,800 起，另有季度订阅 ¥800–3,000 每月。
冷启动阶段报低价是为了买案例和评价——第一次成交的目标是拿到代码和建立信任，不是赚这一单。
案例攒够 5 个、有客户愿意背书之后，标准款提到 1980–2980。
**价格是随信任涨的，不是一次定死的。**

---

## 边界与声明

- 仅对客户**自有或已获得书面授权**的系统执行检测，授权书未签署不启动任何检测动作；
- 自动化检测覆盖不了业务逻辑漏洞、权限设计缺陷、并发竞态类问题，这类需要人工审计；
- 报告不构成对系统安全性的完整保证；
- `samples/` 下的所有密钥、口令均为虚构值，不指向任何真实账号。
