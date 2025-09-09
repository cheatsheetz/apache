# Apache HTTP Server Cheat Sheet

## Installation
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install apache2

# CentOS/RHEL/Fedora
sudo dnf install httpd  # or yum install httpd

# Enable and start
sudo systemctl enable apache2  # or httpd
sudo systemctl start apache2   # or httpd
```

## Configuration Files
```bash
# Main configuration files
/etc/apache2/apache2.conf        # Ubuntu/Debian main config
/etc/httpd/conf/httpd.conf       # CentOS/RHEL main config
/etc/apache2/sites-available/    # Virtual host configs (Ubuntu)
/etc/httpd/conf.d/               # Additional configs (CentOS)
/var/log/apache2/                # Log files (Ubuntu)
/var/log/httpd/                  # Log files (CentOS)
```

## Basic Configuration
```apache
# httpd.conf / apache2.conf
ServerRoot "/etc/apache2"
PidFile /var/run/apache2.pid
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# MPM Configuration
<IfModule mpm_prefork_module>
    StartServers          8
    MinSpareServers       5
    MaxSpareServers      20
    ServerLimit         256
    MaxRequestWorkers   256
    MaxConnectionsPerChild   0
</IfModule>

# Security
ServerTokens Prod
ServerSignature Off
```

## Virtual Hosts
```apache
# /etc/apache2/sites-available/mysite.conf
<VirtualHost *:80>
    ServerName mysite.com
    ServerAlias www.mysite.com
    DocumentRoot /var/www/mysite
    
    ErrorLog ${APACHE_LOG_DIR}/mysite_error.log
    CustomLog ${APACHE_LOG_DIR}/mysite_access.log combined
    
    <Directory /var/www/mysite>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

# SSL Virtual Host
<VirtualHost *:443>
    ServerName mysite.com
    DocumentRoot /var/www/mysite
    
    SSLEngine on
    SSLCertificateFile /path/to/certificate.crt
    SSLCertificateKeyFile /path/to/private.key
    SSLCertificateChainFile /path/to/chainfile.crt
    
    # SSL Security
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
    
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

## .htaccess Examples
```apache
# URL Rewriting
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?url=$1 [QSA,L]

# Force HTTPS
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Cache static files
<FilesMatch "\.(css|js|png|jpg|jpeg|gif|ico|svg)$">
    ExpiresActive On
    ExpiresDefault "access plus 1 year"
    Header append Cache-Control "public"
</FilesMatch>

# Deny access to sensitive files
<Files ~ "^\.ht">
    Require all denied
</Files>

<Files ~ "\.ini$">
    Require all denied
</Files>

# Password protection
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /path/to/.htpasswd
Require valid-user

# IP-based access control
<RequireAll>
    Require ip 192.168.1
    Require ip 10.0.0
</RequireAll>

# Rate limiting (mod_limitipconn)
<Location />
    MaxConnPerIP 10
</Location>
```

## SSL/TLS Configuration
```apache
# Load SSL module
LoadModule ssl_module modules/mod_ssl.so

# Global SSL configuration
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

# Perfect Forward Secrecy
SSLOpenSSLConfCmd DHParameters /path/to/dhparam.pem

# HSTS Header
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName mysite.com
    Redirect permanent / https://mysite.com/
</VirtualHost>
```

## Performance Optimization
```apache
# Compression
LoadModule deflate_module modules/mod_deflate.so
<Location />
    SetOutputFilter DEFLATE
    SetEnvIfNoCase Request_URI \
        \.(?:gif|jpe?g|png)$ no-gzip dont-vary
    SetEnvIfNoCase Request_URI \
        \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary
</Location>

# Caching
LoadModule expires_module modules/mod_expires.so
ExpiresActive On
ExpiresByType text/css "access plus 1 year"
ExpiresByType application/javascript "access plus 1 year"
ExpiresByType image/png "access plus 1 year"
ExpiresByType image/jpg "access plus 1 year"
ExpiresByType image/jpeg "access plus 1 year"
ExpiresByType image/gif "access plus 1 year"
ExpiresByType image/ico "access plus 1 year"

# Headers for caching
<FilesMatch "\.(css|js|png|jpg|jpeg|gif|ico)$">
    Header set Cache-Control "max-age=31536000, public"
</FilesMatch>

# KeepAlive optimization
KeepAlive On
KeepAliveTimeout 2
MaxKeepAliveRequests 50
```

## Security Configuration
```apache
# Hide server information
ServerTokens Prod
ServerSignature Off

# Disable unnecessary modules
#LoadModule autoindex_module modules/mod_autoindex.so
#LoadModule status_module modules/mod_status.so

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Disable server-status and server-info
<Location "/server-status">
    Require all denied
</Location>

<Location "/server-info">
    Require all denied
</Location>

# File upload restrictions
LimitRequestBody 10485760  # 10MB limit

# Directory listing
Options -Indexes

# Remove etags for better caching
FileETag None

# Prevent access to git files
<DirectoryMatch "\.git">
    Require all denied
</DirectoryMatch>
```

## Common Modules
```apache
# Essential modules
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule deflate_module modules/mod_deflate.so
LoadModule expires_module modules/mod_expires.so
LoadModule headers_module modules/mod_headers.so

# Security modules
LoadModule security2_module modules/mod_security2.so
LoadModule evasive24_module modules/mod_evasive24.so

# Performance modules
LoadModule cache_module modules/mod_cache.so
LoadModule cache_disk_module modules/mod_cache_disk.so
```

## Log Configuration
```apache
# Log formats
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Custom log format with response time
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %D" combined_with_time

# Virtual host logs
CustomLog logs/access.log combined
ErrorLog logs/error.log

# Conditional logging
SetEnvIf Remote_Addr "127\.0\.0\.1" dontlog
CustomLog logs/access.log common env=!dontlog
```

## Commands
```bash
# Test configuration
sudo apache2ctl configtest  # Ubuntu/Debian
sudo httpd -t               # CentOS/RHEL

# Reload configuration
sudo systemctl reload apache2
sudo systemctl reload httpd

# Enable/disable sites (Ubuntu/Debian)
sudo a2ensite mysite.conf
sudo a2dissite 000-default.conf

# Enable/disable modules
sudo a2enmod rewrite
sudo a2enmod ssl
sudo a2dismod autoindex

# Check enabled modules
apache2ctl -M
httpd -M

# Check virtual hosts
apache2ctl -S
httpd -S

# Monitor processes
ps aux | grep apache2
ps aux | grep httpd

# Check listening ports
netstat -tulpn | grep :80
netstat -tulpn | grep :443
```

## Monitoring
```apache
# Enable server status (be careful with security)
<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    Require ip 192.168.1.0/24
</Location>

# Enable server info
<Location "/server-info">
    SetHandler server-info
    Require ip 127.0.0.1
</Location>

# Check status
curl http://localhost/server-status
curl http://localhost/server-info
```

## Troubleshooting
```bash
# Check error logs
tail -f /var/log/apache2/error.log
tail -f /var/log/httpd/error_log

# Check access logs
tail -f /var/log/apache2/access.log

# Debug SSL
openssl s_client -connect mysite.com:443

# Test configuration
apache2ctl -t
httpd -t

# Check file permissions
ls -la /var/www/
```

## Official Links
- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)
- [Apache Modules](https://httpd.apache.org/docs/2.4/mod/)
- [Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)