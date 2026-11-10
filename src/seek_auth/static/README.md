# Swagger UI 静态资源（随包发布）

这三个文件来自 npm 包 `swagger-ui-dist@5.17.14`，是 jsdelivr CDN 上
`swagger-ui-dist@5` 的那一份（FastAPI 默认引用的版本）。

**为什么要随包发布**：FastAPI 默认让 `/docs` 从 `cdn.jsdelivr.net` 加载，
国内网络下该 CDN 会间歇失败（实测 `ERR_NETWORK_CHANGED` →
`SwaggerUIBundle is not defined`），文档页变白板。本服务自己托管这些资源，
离线 / 内网 / 无外网环境也能打开 `/docs`。

**升级方式**：换版本时连目录一起替换，保持三个文件名不变即可。

```bash
V=5.17.14
BASE="https://cdn.jsdelivr.net/npm/swagger-ui-dist@$V"
curl -sSLO "$BASE/swagger-ui.css"
curl -sSLO "$BASE/swagger-ui-bundle.js"
curl -sSLO "$BASE/swagger-ui-standalone-preset.js"
```

`app.py` 的 `_static_dir()` 负责定位本目录；找不到时 `/docs` 自动回退 CDN。
