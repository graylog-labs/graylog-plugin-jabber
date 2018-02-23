-- Self-signed certificate
VirtualHost "example.net"
    enable = true
    ssl = {
        certificate = "/etc/prosody/ssl/selfsigned.pem";
        key = "/etc/prosody/ssl/cert-key.pem";
    }