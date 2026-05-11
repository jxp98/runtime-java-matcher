# Runtime Java Matcher

这是一个面向 `Wazuh manager -> runtime Java inventory` 场景的最小可运行组件漏洞匹配服务。

## 目标

- 接收 manager 发送的运行态 Java 组件清单
- 按 `purl / sha1 / groupId:artifactId / artifactId` 进行组件归一化匹配
- 按本地漏洞数据库判断版本是否命中漏洞区间
- 返回标准 `matches` 响应，供 manager 落入 `wazuh-states-vulnerabilities-runtime-java`

## 当前能力

- HTTP 接口：
  - `GET /healthz`
  - `POST /runtime-java/match`
- 支持匹配键：
  - `purl`
  - `sha1`
  - `group_id + artifact_id`
  - `artifact_id` 兜底
- 支持版本范围：
  - `>=2.0,<2.15.0`
  - `<=1.0.0`
  - `1.2.3||2.0.0`
- 支持两类漏洞数据源：
  - 单文件原生 JSON：`testdata/vulndb.json`
  - 目录 bundle：`testdata/formal-db/`
- 自带示例请求：`testdata/request.json`

## 启动

```bash
go run ./cmd/server
```

也可以显式指定 bundle 目录：

```bash
RUNTIME_JAVA_MATCHER_ADDR=":18080" \
RUNTIME_JAVA_MATCHER_DB="testdata/formal-db" \
go run ./cmd/server
```

## 离线匹配 CLI

如果当前环境不方便直接监听端口，也可以直接离线跑一次匹配：

```bash
go run ./cmd/matchcli -db testdata/vulndb.json -request testdata/request.json
```

如果要测试正式目录库格式：

```bash
go run ./cmd/matchcli -db testdata/formal-db -request testdata/request.json
```

示例输出已生成到：`testdata/response.json`

## 目录 bundle 格式

`runtime-java-matcher` 现在支持更适合生产维护的目录库格式：

```text
testdata/formal-db/
├── metadata.json
└── packages/
    └── maven-core.json
```

`metadata.json` 示例：

```json
{
  "format": "runtime-java-bundle",
  "source": "trivy-java-export",
  "version": "2025.01.0",
  "generated_at": "2025-01-01T00:00:00Z"
}
```

包记录文件示例：

```json
{
  "packages": [
    {
      "package_type": "maven",
      "group_id": "org.apache.logging.log4j",
      "artifact_id": "log4j-core",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
      "vulnerabilities": [
        {
          "id": "CVE-2021-44228",
          "affected_range": ">=2.0,<2.15.0",
          "fixed_versions": ["2.15.0"]
        }
      ]
    }
  ]
}
```

## 与 Trivy 的衔接建议

当前 matcher 现在支持两种数据面：一是现有的 bundle 目录，二是直接读取原始 `trivy.db + trivy-java.db` 的 `trivy-raw` 后端。

如果要继续把这条路做成正式能力，建议直接参考项目级设计文档：`docs/runtime-java-trivy-bundle-design.md`。

推荐后续演进路径：

1. 保持当前 matcher 服务边界不变
2. 将 Trivy / 内部漏洞源导出的 Java advisory 预处理为上述 bundle 目录
3. 由 matcher 直接加载 bundle，继续向 Wazuh manager 暴露统一协议

这样可以逐步切换到 Trivy 风格的正式数据源，而不用重写 manager 侧协议与索引逻辑。

## bundlegen

如果已经有上游预处理后的标准化导出 JSON，可以先用 `bundlegen` 生成正式 bundle：

```bash
go run ./cmd/bundlegen \
  -input testdata/bundlegen/input \
  -output dist/runtime-java-bundle \
  -version 2026.05.0 \
  -advisory-source trivy-db
```

当前 `bundlegen` 现在支持三类输入：

- 标准化导出 JSON（当前首版主路径）
- `Trivy JSON report`（按保守原则导入为“精确版本规则”）
- `trivy-advisory-export`（建议的正式 Trivy advisory 导出格式）

目录输入下，`bundlegen` 会自动收集：

- `*.json`
- `*.json.golden`
- `*.golden.json`

这意味着在本机工作区里，可以直接把只包含 Trivy 报告 JSON 的目录（例如 `testdata/bundlegen/trivy-integration-reports`）拿来做 seed bundle 输入。

当前仍然**没有直接读取 Trivy 原始数据库**；更推荐在 local 端先把 Trivy 数据预处理/导出，再交给 `bundlegen` 生成正式 bundle。

如果 local 端已经拿到了 Trivy DB 的逻辑导出目录（例如包含 `java.yaml`、`vulnerability.yaml`、`data-source.yaml`），可以先执行：

```bash
go run ./cmd/trivyexport -input-dir testdata/trivyexport/db -output dist/trivy-advisory-export.json
```

然后再把生成的 `trivy-advisory-export.json` 交给 `bundlegen`：

```bash
go run ./cmd/bundlegen \
  -input dist/trivy-advisory-export.json \
  -output dist/runtime-java-bundle \
  -advisory-source trivy-db
```

如果想在当前仓库里快速生成一个更丰富的本机 seed bundle，可以直接复用已经 vendoring 进来的 Trivy Java 样本：

```bash
rm -rf dist && mkdir -p dist

go run ./cmd/trivyexport \
  -input-dir testdata/trivyexport/db \
  -output dist/trivy-advisory-export.json

go run ./cmd/bundlegen \
  -input testdata/formal-db,dist/trivy-advisory-export.json,testdata/bundlegen/trivy-integration-reports,testdata/bundlegen/trivy-report.json \
  -output dist/runtime-java-seed-bundle \
  -version 2026.05.0 \
  -advisory-source trivy-db
```

其中：

- `testdata/trivyexport/db`：Trivy Java advisory 逻辑导出样本
- `testdata/bundlegen/trivy-integration-reports`：Trivy integration 的真实 Java 扫描报告样本
- `testdata/bundlegen/trivy-report.json`：当前项目已有的 runtime-java 真实样本补充

这条命令的价值不是直接替代正式 `trivy-db`，而是先把仓库内现有可复用的 Trivy Java 样本尽量并进来，让远端验证时不再只拿到 3 条演示库。

## Trivy 对照回归

如果你想回答“当前 matcher 的漏洞命中语义和 Trivy 官方结果差多少”，现在可以直接用 `trivycompare` 做一轮**对照回归**。

它的思路是：

1. 读取一份 **Trivy 官方 JSON 报告**
2. 从报告中抽取组件身份与版本，自动合成一份 matcher request
3. 调当前 matcher
4. 对比：
   - `Trivy 有、matcher 没有`
   - `matcher 有、Trivy 没有`

这条路径优先验证的是**漏洞匹配与版本判断语义**，而不是 agent 采集差异。

### 本地 bundle 对照

```bash
go run ./cmd/trivycompare \
  -trivy-report testdata/bundlegen/trivy-report.json \
  -db testdata/formal-db \
  -request-out dist/trivy-compare.request.json \
  -response-out dist/trivy-compare.response.json
```

### 对在线 matcher 服务做对照

```bash
go run ./cmd/trivycompare \
  -trivy-report /path/to/trivy-report.json \
  -matcher-url http://127.0.0.1:8080/runtime-java/match \
  -request-out dist/trivy-compare.request.json \
  -response-out dist/trivy-compare.response.json
```

输出会给出：

- `baseline_components`
- `baseline_vulnerabilities`
- `matcher_components`
- `matcher_vulnerabilities`
- `missing_in_matcher`
- `extra_in_matcher`

如果要做更完整的回归，建议保存三份产物：

- Trivy 原始报告
- `trivycompare` 生成的 request
- 当前 matcher 返回的 response

这样后续每次优化都能做稳定 diff。

## 联调示例

```bash
curl -s http://127.0.0.1:8080/healthz

curl -s \
  -H 'Content-Type: application/json' \
  --data @testdata/request.json \
  http://127.0.0.1:8080/runtime-java/match | jq
```

## 与 Wazuh manager 对接

manager 侧配置示例：

```xml
<vulnerability-detection>
  <enabled>yes</enabled>
  <runtime_java>
    <enabled>yes</enabled>
    <matcher_url>http://127.0.0.1:8080/runtime-java/match</matcher_url>
    <matcher_source>trivy-java</matcher_source>
    <request_timeout>30</request_timeout>
    <batch_size>500</batch_size>
    <result_index>wazuh-states-vulnerabilities-runtime-java</result_index>
  </runtime_java>
</vulnerability-detection>
```

## 响应结构

```json
{
  "request_id": "demo-session-001",
  "schema_version": "1.0",
  "generated_at": "2025-01-01T00:00:00Z",
  "source": "runtime-java-matcher",
  "scan_mode": "full",
  "matches": [
    {
      "inventory_id": "runtime-java:component-1",
      "component_ref": "runtime-java:component-1",
      "match_confidence": "high",
      "component": {
        "group_id": "org.apache.logging.log4j",
        "artifact_id": "log4j-core",
        "version": "2.14.1"
      },
      "vulnerabilities": [
        {
          "id": "CVE-2021-44228",
          "severity": "critical",
          "affected_range": ">=2.0,<2.15.0",
          "fixed_versions": ["2.15.0"]
        }
      ]
    }
  ]
}
```

## 测试

```bash
go test ./...
```

## 当前边界

- 这是最小可运行版本，不是完整 Trivy 替代品
- 当前已经支持直接读取 Trivy 原始 DB，也保留了 bundle 目录后端以便灰度切换
- `bundle` 后端仍沿用工程化近似版本比较；`trivy-raw` 后端优先采用 Maven 语义约束匹配
- 当前未实现删除语义推导；如需删除，manager 可依赖 full scan 清旧结果，或后续扩展 matcher 显式返回 `operation=delete`


## 直接使用 Trivy 原始库（方案 B）

如果你希望远端直接挂载原始 `trivy-db + trivy-java-db`，现在可以使用 `trivy-raw` 后端：

```bash
RUNTIME_JAVA_MATCHER_BACKEND="trivy-raw" RUNTIME_JAVA_MATCHER_TRIVY_CACHE_DIR="/opt/OWNHIDS/TRIVY-DB/trivy-cache" go run ./cmd/server
```

也支持分别指定两个库：

```bash
RUNTIME_JAVA_MATCHER_BACKEND="trivy-raw" RUNTIME_JAVA_MATCHER_TRIVY_VULN_DB="/opt/OWNHIDS/TRIVY-DB/trivy-cache/db" RUNTIME_JAVA_MATCHER_TRIVY_JAVA_DB="/opt/OWNHIDS/TRIVY-DB/trivy-cache/java-db" go run ./cmd/server
```

这个后端的关键行为是：

- 直接读取 `trivy.db` 中的 Maven advisory，而不是先导出 bundle
- 直接读取 `trivy-java.db` 做 `sha1 -> groupId:artifactId:version` 补全
- 对版本命中逻辑优先贴近 Trivy Maven 约束语义
- 兼容 manager 传来的“原始 inventory 文档”输入，而不要求先改成扁平组件 JSON
