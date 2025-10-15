# API 版本化说明

## 路由结构

### 传统路由（向后兼容，无版本前缀）
```
GET  /capsule/{id}              - 获取胶囊
POST /capsule/                  - 创建胶囊
GET  /capsule/owner/{owner_id}  - 获取所有者的胶囊
GET  /capsule/search            - 搜索胶囊

POST /auth/grant                - 授予权限
POST /auth/use                  - 使用令牌
POST /auth/revoke               - 撤销权限
GET  /auth/list                 - 列出权限
```

### V1 API（显式版本）
```
GET  /v1/capsule/{id}              - 获取胶囊
POST /v1/capsule/                  - 创建胶囊
GET  /v1/capsule/owner/{owner_id}  - 获取所有者的胶囊
GET  /v1/capsule/search            - 搜索胶囊

POST /v1/auth/grant                - 授予权限
POST /v1/auth/use                  - 使用令牌
POST /v1/auth/revoke               - 撤销权限
GET  /v1/auth/list                 - 列出权限
```

### V2 API（新功能）
```
POST /v2/capsule/upload         - 上传文件并创建完整胶囊（Cap0 + Cap1）
```

## 代码结构

```
src/
├── handlers/
│   ├── mod.rs           # 导出 v1 和 v2，并为向后兼容重新导出 v1
│   ├── v1/              # V1 handlers
│   │   ├── mod.rs
│   │   ├── capsule.rs   # V1 胶囊处理
│   │   └── authorization.rs  # V1 授权处理
│   └── v2/              # V2 handlers
│       ├── mod.rs
│       └── capsule.rs   # V2 胶囊处理（文件上传）
│
├── routes/
│   ├── mod.rs           # 主路由配置
│   ├── capsule.rs       # 传统路由（向后兼容）
│   ├── authorization.rs # 传统路由（向后兼容）
│   ├── v1/              # V1 routes
│   │   ├── mod.rs
│   │   ├── capsule.rs
│   │   └── authorization.rs
│   └── v2/              # V2 routes
│       ├── mod.rs
│       └── capsule.rs
```

## 访问 Swagger UI

启动服务器后访问：
```
http://localhost:8080/swagger-ui
```

所有 API 文档都会在 Swagger UI 中展示，包括：
- 传统路由（无版本前缀）
- V1 API
- V2 API

## 开发指南

### 添加新的 V2 端点

1. 在 `src/handlers/v2/` 中添加 handler 函数
2. 在 `src/routes/v2/` 中添加路由配置
3. 使用 `#[utoipa::path]` 标注生成 OpenAPI 文档

### 示例：V2 Upload Handler

```rust
// src/handlers/v2/capsule.rs
#[utoipa::path(
    post,
    path = "/upload",
    request_body(content = UploadRequest, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "Capsule created", body = UploadResponse),
    ),
    tag = "Capsule V2"
)]
pub async fn upload_and_create_capsule(
    // ... implementation
) -> Result<Json<UploadResponse>> {
    // ...
}
```

## 下一步工作

V2 API 当前只有占位符实现，需要完成：

1. 文件上传处理（multipart/form-data）
2. 文本提取服务
3. BNF 解析服务
4. 元数据生成
5. Cap0 + Cap1 完整封装流程
6. 对象存储集成

详见开发任务列表。
