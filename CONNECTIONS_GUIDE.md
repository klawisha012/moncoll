# Connections / Proxy Feature - User Guide

## Overview

The **Connections** tab allows you to configure site connections (proxy rules) that dynamically generate Nginx/Angie configuration files. Each connection defines how traffic should be proxied from the WAF to your backend applications.

## Architecture

```
Client → Angie WAF (Port 80/443) → Your Backend Application
         ↓
    ModSecurity Inspection
    + Dynamic Proxy Rules
```

### How It Works

1. **Connection Definition**: You create a connection with domains and backend URL
2. **Config Generation**: The system automatically generates an Nginx server block in `/etc/angie/connections.d/{id}.conf`
3. **Auto-Inclusion**: The main `angie.conf` includes all files from `connections.d/` directory
4. **Reload**: After adding/modifying connections, click "Reload Nginx" to apply changes

## Quick Start

### Option 1: Test with Example Backend (Local Development)

1. **Start the example backend** (optional, for testing):

   ```bash
   python3 examples/test_backend.py
   ```

2. **Add hosts file entry** (required for domain-based routing):

   - **Mac/Linux**: Edit `/etc/hosts`
   - **Windows**: Edit `C:\Windows\System32\drivers\etc\hosts` (as Administrator)

   Add:
   ```
   127.0.0.1  local.waf.test
   127.0.0.1  test.waf.local
   ```

3. **Create a Connection in the WAF UI**:

   - Go to **Connections** tab
   - Click **Add Connection**
   - Fill in the form:
     ```
     Name:        Example Test Site
     Domains:    local.waf.test
                 test.waf.local (optional second domain)
     Backend URL: http://host.docker.internal:5000   [Mac/Windows]
                  http://172.17.0.1:5000            [Linux]
     Enabled:    ✓ Checked
     SSL:        ✗ Not enabled (for local testing)
     ```
   - Click **Create**

4. **Reload Nginx**:
   - Click the green **Reload Nginx** button
   - Wait for success message

5. **Test the connection**:
   - Open browser: `http://local.waf.test`
   - You should see the example HTML page
   - All requests are logged and inspected by ModSecurity

### Option 2: Connect Your Existing Application

#### Static Site (HTML + CSS + JS)

If you have a static site:

1. **Serve your static files** with any HTTP server:

   ```bash
   # Using Python
   cd /path/to/your/site
   python3 -m http.server 8080

   # OR using Node.js
   npx serve -p 8080 /path/to/site
   ```

2. **Create connection**:
   ```
   Name:        My Static Site
   Domains:    mysite.example.com
   Backend URL: http://host.docker.internal:8080
   Enabled:    ✓
   ```

3. **DNS Configuration**: Point `mysite.example.com` to your WAF's public IP

4. **Reload Nginx** and test

#### React / Vue / Angular App

For SPAs with client-side routing:

```
Name:        React App
Domains:    app.example.com
Backend URL: http://host.docker.internal:3000
Enabled:    ✓
Custom Nginx Config: |
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
```

#### Node.js / Python / PHP Backend

For API backends or full-stack apps:

```
Name:        API Backend
Domains:    api.example.com
Backend URL: http://host.docker.internal:8000
Enabled:    ✓
Preserve Host: ✓ (recommended for proper logging)
```

## Important Notes

### Docker Network Addressing

When WAF runs in Docker, your backend is accessed from **inside** the Angie container:

- **Mac/Windows Docker Desktop**: Use `host.docker.internal` to reach host machine
- **Linux Docker**: Use `172.17.0.1` (Docker bridge gateway) or expose port on `0.0.0.0`

Examples:

| Your Backend (Host) | Backend URL in Connection |
|---------------------|--------------------------|
| `http://localhost:3000` | `http://host.docker.internal:3000` |
| `http://localhost:8080` | `http://host.docker.internal:8080` |
| `http://127.0.0.1:8000` | `http://172.17.0.1:8000` (Linux) |

### SSL/TLS Configuration

For production with HTTPS:

1. **Upload certificates** to the Angie container:
   ```bash
   # Via docker-compose volumes or docker cp
   docker cp cert.pem waf-angie-1:/etc/angie/ssl/
   docker cp key.pem waf-angie-1:/etc/angie/ssl/
   ```

2. **Enable SSL** in connection:
   ```
   SSL Enabled:      ✓
   SSL Cert Path:    /etc/angie/ssl/cert.pem
   SSL Key Path:     /etc/angie/ssl/key.pem
   ```

3. **Ports**: The connection automatically listens on both 80 and 443

### Connection Options

| Field | Description | Example |
|-------|-------------|---------|
| **Name** | Human-readable identifier | "Production API" |
| **Domains** | Server names (one per line) | `api.example.com`<br>`api.internal` |
| **Backend URL** | Where to proxy requests | `http://backend:8000` |
| **Enabled** | Toggle without deleting | ✓ |
| **SSL Enabled** | Enable HTTPS listening | ✓ |
| **SSL Cert Path** | Path inside Angie container | `/etc/angie/ssl/cert.pem` |
| **SSL Key Path** | Path inside Angie container | `/etc/angie/ssl/key.pem` |
| **Preserve Host** | Pass original Host header | ✓ (recommended) |
| **Custom Nginx Config** | Additional directives | `proxy_buffering off;` |

## Generated Nginx Configuration

Each connection creates a file in `/etc/angie/connections.d/{id}.conf`:

```nginx
## Connection: My Site (ID: 1)
## Generated at: 2026-04-19T19:30:00Z

server {
    listen 80;
    listen 443 ssl;                    # if SSL enabled
    ssl_certificate /path/to/cert.pem; # if SSL enabled
    ssl_certificate_key /path/to/key.pem;
    server_name example.com www.example.com;

    # ModSecurity WAF protection
    ModSecurityEnabled on;
    ModSecurityConfig /etc/angie/modsecurity/modsecurity.conf;
    ModSecurityRulesFile /etc/angie/modsecurity/rules.conf;

    # Proxy to backend
    proxy_pass http://backend:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_redirect off;

    # Custom config (if specified)
    # proxy_buffering off;
}
```

## Testing Your Setup

1. **Check Nginx configuration**:
   ```bash
   docker exec waf-angie-1 angie -t
   ```

2. **View generated config**:
   ```bash
   docker exec waf-angie-1 cat /etc/angie/connections.d/1.conf
   ```

3. **Test request**:
   ```bash
   curl -I http://local.waf.test
   ```

4. **Monitor logs**:
   ```bash
   docker logs waf-angie-1 -f
   ```

5. **Check WAF Dashboard**: Open Grafana to see request analytics

## Troubleshooting

### "Backend not reachable" error

**Issue**: WAF can't connect to your backend

**Solutions**:
- Ensure backend is running and accessible from Docker container
- Check firewall rules
- Use correct host address (`host.docker.internal` or `172.17.0.1`)

### Domains not resolving

**Issue**: Browser doesn't reach WAF

**Solutions**:
- Add domain to `/etc/hosts` (as shown above)
- Verify DNS points to WAF's public IP in production
- Test with `curl -H "Host: yourdomain.com" http://WAF_IP`

### 502 Bad Gateway

**Issue**: Backend returns error

**Solutions**:
- Verify backend URL is correct and accessible
- Check backend is listening on correct interface (0.0.0.0, not 127.0.0.1)
- Ensure no port conflicts

### Changes not applying

**Issue**: Updated connection but site behavior unchanged

**Solutions**:
- Click **Reload Nginx** button
- Check `docker logs waf-angie-1` for config errors
- Verify config file exists: `docker exec waf-angie-1 ls /etc/angie/connections.d/`

## Production Deployment

For production use:

1. **Secure your backends**: Don't expose backends directly to internet
2. **Enable SSL**: Use Let's Encrypt or commercial certificates
3. **Configure DNS**: Point domains to WAF's public IP
4. **Set up monitoring**: Use Grafana dashboards
5. **Enable rate limiting**: Add custom Nginx config per connection
6. **Custom ModSecurity rules**: Tune rules for your application

### Example Production Config

```
Name:        Production API
Domains:    api.example.com
Backend URL: http://api_backend:8000
SSL Enabled: ✓
SSL Cert Path: /etc/angie/ssl/example.com.crt
SSL Key Path: /etc/angie/ssl/example.com.key
Custom Config: |
    limit_req zone=api burst=20 nodelay;
    client_max_body_size 10M;
    proxy_connect_timeout 5s;
    proxy_send_timeout 30s;
    proxy_read_timeout 30s;
```

## Next Steps

- Explore ModSecurity rules in **Configuration → ModSecurity** tab
- Monitor traffic in **Dashboard** with Grafana
- Tune WAF settings for your specific needs
- Set up automated certificate renewal (Let's Encrypt)

---

**Need help?** Check the project README or open an issue on GitHub.
