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

当前 matcher 还没有直接内嵌 Trivy 的漏洞库读取代码，但已经把数据源能力从“样例单文件”升级成了“可维护的正式 bundle 目录”。

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
- 当前还没有直接读取 Trivy 原生 DB，而是为正式 Java advisory bundle 做了加载抽象
- 当前版本比较实现是工程化近似版本，不是完整 Maven 语义实现
- 当前未实现删除语义推导；如需删除，manager 可依赖 full scan 清旧结果，或后续扩展 matcher 显式返回 `operation=delete`
