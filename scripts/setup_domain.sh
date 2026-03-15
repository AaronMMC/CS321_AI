#!/bin/bash
# Setup local test domain for email gateway prototype

# Add to hosts file
echo "127.0.0.1   mail.prototype.local" | sudo tee -a /etc/hosts
echo "127.0.0.1   prototype.local" | sudo tee -a /etc/hosts

# Generate self-signed SSL certificate for the domain
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout config/mail.prototype.local.key \
  -out config/mail.prototype.local.crt \
  -subj "/CN=mail.prototype.local"

echo "Local domain setup complete: prototype.local"
echo "Use mail.prototype.local as your mail server"