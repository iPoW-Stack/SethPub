#!/bin/bash

# Script to copy SSL certificates to all node directories

CERT_FILE="server-cert.pem"
KEY_FILE="server-key.pem"

# Check if certificate files exist in current directory
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Error: Certificate files not found in current directory"
    echo "Please generate certificates first using:"
    echo "  openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj '/CN=localhost'"
    exit 1
fi

echo "Copying certificates to node directories..."

# Find all node directories (assuming they are in /root/seths/)
if [ -d "/root/seths" ]; then
    for dir in /root/seths/s*; do
        if [ -d "$dir" ]; then
            echo "Copying to $dir"
            cp "$CERT_FILE" "$dir/"
            cp "$KEY_FILE" "$dir/"
            chmod 644 "$dir/$CERT_FILE"
            chmod 600 "$dir/$KEY_FILE"
        fi
    done
    echo "Certificates copied successfully!"
else
    echo "Warning: /root/seths directory not found"
    echo "Certificates are available in current directory"
fi

echo ""
echo "Certificate files:"
echo "  - $CERT_FILE"
echo "  - $KEY_FILE"
echo ""
echo "To use HTTPS, ensure these files are in the working directory of your application"
