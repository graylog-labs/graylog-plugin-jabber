-- CA-signed certificate
VirtualHost "example.com"
    enable = true
    ssl = {
        certificate = "/etc/prosody/ssl/server-cert.pem";
        key = "/etc/prosody/ssl/cert-key.pem";
    }