# Custom Domain Setup with Cloudflare (or any DNS provider)

This guide covers pointing a domain or subdomain to your DSFM instance using
Cloudflare as an example. The same principles apply to any DNS provider
(Namecheap, Route 53, Google Domains, etc.).

---

## Overview

```
Browser → Cloudflare (DNS + optional proxy) → your server IP → Nginx → DSFM
```

| Layer | Responsibility |
|-------|---------------|
| DNS provider | Resolves `shop.example.com` to your server's IP |
| Cloudflare proxy (optional) | DDoS protection, CDN caching, free SSL |
| Nginx | TLS termination (if not using Cloudflare proxy), reverse proxy |
| DSFM (Gunicorn) | Application on `127.0.0.1:<port>` |

---

## 1. DNS Records

Log in to your DNS provider's dashboard and create **A** (or **AAAA**) records.

### Single domain

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `@` | `203.0.113.10` | Proxied / DNS only |

### Subdomain

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `shop` | `203.0.113.10` | Proxied / DNS only |

### Multiple subdomains (multi-site)

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| A | `shop` | `203.0.113.10` | Proxied |
| A | `blog` | `203.0.113.10` | Proxied |
| A | `api`  | `203.0.113.10` | Proxied |

All subdomains point to the **same server IP**. Nginx routes each hostname to
the correct DSFM instance.

> Replace `203.0.113.10` with your server's public IP address.

---

## 2. Cloudflare-Specific Settings

### Proxy mode (orange cloud)

When **Proxied** is enabled, Cloudflare sits between the user and your server:

- Free SSL/TLS (edge certificates)
- DDoS protection
- CDN caching for static assets

### SSL/TLS encryption mode

Go to **SSL/TLS → Overview** and choose:

| Mode | When to use |
|------|------------|
| **Full (strict)** | Your origin has a valid SSL certificate (Let's Encrypt or Cloudflare Origin CA) |
| **Full** | Your origin has a self-signed certificate |
| **Flexible** | Your origin serves HTTP only (Nginx proxies to DSFM over HTTP) |

> **Recommended**: Use **Full (strict)** with a free [Cloudflare Origin CA
> certificate](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)
> installed on Nginx.

### Always Use HTTPS

Enable under **SSL/TLS → Edge Certificates → Always Use HTTPS** so
Cloudflare automatically redirects HTTP to HTTPS at the edge.

---

## 3. Server-Side Configuration

### DSFM `config.toml`

```toml
[app]
port = 5001
domain = "shop.example.com"
proxy_mode = true      # trust X-Forwarded-* headers from Nginx
protocol = "http"      # Nginx (or Cloudflare) handles TLS

[security]
session_cookie_secure = true
```

### Nginx

Use Example 2 or 3 from [`deploy/nginx.example.conf`](nginx.example.conf)
matching your subdomain. Summary:

```nginx
server {
    listen 80;
    server_name shop.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name shop.example.com;

    ssl_certificate     /etc/ssl/cloudflare/origin.pem;   # or Let's Encrypt
    ssl_certificate_key /etc/ssl/cloudflare/origin-key.pem;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Cloudflare real IP restoration (optional)

To see real visitor IPs in DSFM logs instead of Cloudflare IPs, add the
[Cloudflare IP ranges](https://www.cloudflare.com/ips/) to Nginx:

```nginx
# /etc/nginx/conf.d/cloudflare.conf
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
# ... (see full list at https://www.cloudflare.com/ips/)
real_ip_header CF-Connecting-IP;
```

---

## 4. Other DNS Providers

The DNS record setup is the same regardless of provider — only the dashboard
UI differs.

| Provider | Dashboard |
|----------|-----------|
| Namecheap | Domain List → Manage → Advanced DNS |
| AWS Route 53 | Hosted Zones → Create Record |
| Google Domains | DNS → Custom Records |
| DigitalOcean | Networking → Domains |

Create an **A record** pointing your (sub)domain to the server IP, then
configure Nginx and DSFM as shown above.

---

## 5. Verifying the Setup

```bash
# Check DNS resolution
dig shop.example.com +short

# Test HTTP → HTTPS redirect
curl -I http://shop.example.com

# Test HTTPS
curl -I https://shop.example.com
```

If using Cloudflare proxy, the `server` header will show `cloudflare`.
