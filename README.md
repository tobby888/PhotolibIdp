# PhotolibIdp

PhotolibIdp 是 PhotoLib 与 Deplyt 等配套服务的统一身份认证与访问准入中心（IdP）。

- **职责边界**：PhotolibIdp 负责集中管理成员账号生命周期（创建、启停、重置密码、删除）、注册码发放与注册申请审核、应用注册（生成 `clientId` 与 `clientSecret`、配置回调 URL）、以及**账号是否有权访问某应用服务**的准入控制；各应用内部的业务细粒度权限（如 PhotoLib 的权限组、校区与图库可见范围）由各应用自行管理。
- **外观策略**：PhotolibIdp 不设图标（Icon），仅展示由管理员在控制台设置的标语（Slogan）。
- **单二进制打包**：后端采用 Go 编写，前端采用 Svelte 5 + Vite 编写，构建时将 `webui/dist` 静态资源直接嵌入 Go 二进制可执行文件中。

---

## 构建与本地验证

需 Go 1.26 与 Node 22+：

```sh
npm --prefix frontend ci
npm --prefix frontend run build
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o photolib-idp .
```

---

## 安装与 systemd 服务配置

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin photolib-idp
sudo install -d -m 0755 /opt/photolib-idp
sudo install -m 0755 photolib-idp /opt/photolib-idp/photolib-idp
sudo install -o root -g photolib-idp -m 0640 .env.example /opt/photolib-idp/.env
sudoedit /opt/photolib-idp/.env
sudo install -m 0644 photolib-idp.service /etc/systemd/system/photolib-idp.service
sudo systemctl daemon-reload
sudo systemctl enable --now photolib-idp
curl -fsS http://127.0.0.1:8090/healthz
```

### `.env` 配置项说明

| 配置 | 用途 |
| --- | --- |
| `IDP_LISTEN_ADDR` | 本地监听地址，默认 `127.0.0.1:8090`，供同机 Nginx HTTPS 反向代理转发。 |
| `IDP_PUBLIC_URL` | PhotolibIdp 的对外 HTTPS 源地址，例如 `https://auth.example.com`。 |
| `IDP_STATE_DIR` | 状态存储目录（保存账号、应用注册、注册码、审核记录与标语设置）。systemd 默认使用 `/var/lib/photolib-idp`。 |
| `IDP_ADMIN_USERNAME` | 首次启动且尚无管理员时创建的初始管理员账号，默认 `admin`。 |
| `IDP_ADMIN_DISPLAY_NAME` | 初始管理员显示姓名，默认 `系统管理员`。 |
| `IDP_ADMIN_PASSWORD` | 初始管理员密码，首次启动自动创建管理员后可清空。 |
| `IDP_ADMIN_EMAIL` | 可选，初始管理员邮箱。 |

---

## Nginx 反向代理配置示范

将以下配置放入 PhotolibIdp 域名（如 `auth.example.com`）的 Nginx 配置中。OAuth 授权回调与令牌兑换接口建议关闭访问日志或避免记录敏感查询参数，同时透传 `X-Real-IP` 供注册申请接口按客户端真实 IP 限流：

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/nginx/ssl/auth.example.com.pem;
    ssl_certificate_key /etc/nginx/ssl/auth.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 1m;

    location = /healthz {
        access_log off;
        proxy_pass http://127.0.0.1:8090;
    }

    location = /oauth/authorize {
        access_log off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://127.0.0.1:8090;
    }

    location /api/v1/oauth/ {
        access_log off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://127.0.0.1:8090;
    }

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
        proxy_pass http://127.0.0.1:8090;
    }
}
```

---

## 应用注册与对接流程（PhotoLib & Deplyt）

1. 使用管理员账号登录 PhotolibIdp，进入 **「应用注册与准入」**：
   - **注册 PhotoLib**：
     - 应用名称：`PhotoLib`
     - Client ID：`photolib`（或自动生成）
     - 回调 URL：`https://photolib.example.com/auth/callback`
     - 访问准入策略：选择「允许全部已启用的认证中心账号登录」（`ALL_AUTHENTICATED`）或按名单授权。
     - 复制生成的 `Client ID` 和 `Client Secret` 填入 PhotoLib 的 `.env`：
       ```properties
       IDP_PUBLIC_URL=https://auth.example.com
       IDP_CLIENT_ID=photolib
       IDP_CLIENT_SECRET=生成的密钥
       ```
   - **注册 Deplyt**：
     - 应用名称：`Deplyt`
     - Client ID：`deplyt`
     - 回调 URL：`https://deploy.example.com/auth/callback`
     - 访问准入策略：选择「仅允许管理员和下方勾选的账号登录」（`RESTRICTED`），勾选允许进入部署平台的成员。
     - 复制生成的 `Client ID` 和 `Client Secret` 填入 Deplyt 的 `.env`：
       ```dotenv
       IDP_PUBLIC_URL=https://auth.example.com
       IDP_CLIENT_ID=deplyt
       IDP_CLIENT_SECRET='生成的密钥'
       ```
2. **注册码与注册审核**：
   - 管理员在 PhotolibIdp 的 **「注册码」** 页新建注册码（可勾选审核通过后自动授予访问权的应用），把注册码与 PhotolibIdp 注册页链接（`https://auth.example.com/#register`）发给新成员。
   - 新成员提交申请后，管理员在 **「注册审核」** 页一键通过即可建号并授予应用访问权。
