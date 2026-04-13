# SSL Certificate Generation for Nodes

## Overview

Each node now automatically generates its own self-signed SSL certificate for HTTPS support. This ensures secure communication between clients and the HTTP API server.

## Automatic Generation (temp_cmd.sh)

The `temp_cmd.sh` script has been updated to automatically generate SSL certificates when deploying nodes.

### What it does:
1. Creates a unique self-signed certificate for each node
2. Generates both certificate (`server-cert.pem`) and private key (`server-key.pem`)
3. Sets proper file permissions (cert: 644, key: 600)
4. Uses the local IP address as the Common Name (CN)

### Certificate Details:
- **Algorithm**: RSA 2048-bit
- **Validity**: 365 days
- **Subject**: `/C=CN/ST=State/L=City/O=Seth/OU=Node/CN=<local_ip>`
- **Files**:
  - Certificate: `/root/seths/s<shard>_<node>/server-cert.pem`
  - Private Key: `/root/seths/s<shard>_<node>/server-key.pem`

## Manual Generation (generate_node_certs.sh)

For existing nodes that don't have certificates, use the standalone script:

```bash
cd /root/seth
./generate_node_certs.sh
```

### Features:
- Scans all node directories in `/root/seths/`
- Skips nodes that already have certificates
- Generates certificates for nodes that need them
- Provides detailed progress output
- Sets correct file permissions automatically

### Example Output:
```
Generating SSL certificates for all nodes in /root/seths
Using local IP: 10.10.1.115

Generating certificate for s3_1...
  ✓ Certificate generated: /root/seths/s3_1/server-cert.pem
  ✓ Private key generated: /root/seths/s3_1/server-key.pem

Generating certificate for s3_10...
  ✓ Certificate generated: /root/seths/s3_10/server-cert.pem
  ✓ Private key generated: /root/seths/s3_10/server-key.pem

==========================================
Certificate generation complete!
Generated certificates for 2 nodes
==========================================
```

## Verification

### Check if certificate exists:
```bash
ls -la /root/seths/s3_1/server-*.pem
```

Expected output:
```
-rw-r--r-- 1 root root 1234 Apr 12 10:00 server-cert.pem
-rw------- 1 root root 1704 Apr 12 10:00 server-key.pem
```

### View certificate details:
```bash
openssl x509 -in /root/seths/s3_1/server-cert.pem -text -noout
```

### Test HTTPS connection:
```bash
curl -k -X POST https://127.0.0.1:23001/query_account -d "address=test"
```

## How It Works in Code

The HTTP handler (`src/init/http_handler.cc`) searches for certificates in multiple locations:

1. Current directory: `./server-cert.pem`
2. Parent directory: `../server-cert.pem`
3. Grandparent directory: `../../server-cert.pem`
4. Absolute path: `/root/seth/server-cert.pem`

This ensures certificates are found regardless of the working directory.

## Security Considerations

### Development/Testing:
- Self-signed certificates are appropriate
- Clients must use `-k` flag with curl or `verify=False` in Python
- SSL warnings are expected and can be suppressed

### Production:
- Consider using CA-signed certificates
- Update certificate paths in code or use environment variables
- Implement certificate rotation (365-day validity)
- Use stronger keys (4096-bit RSA or ECDSA)

## Troubleshooting

### Certificate not found error:
```
SETH_ERROR("Certificate or key file not found!")
```

**Solution**: Run `generate_node_certs.sh` to create certificates

### Permission denied error:
```
Error reading private key
```

**Solution**: Check file permissions
```bash
chmod 600 /root/seths/s3_1/server-key.pem
chmod 644 /root/seths/s3_1/server-cert.pem
```

### HTTPS server not listening:
```bash
netstat -nlp | grep 23001
# No output
```

**Solution**: 
1. Check if certificates exist
2. Check server logs for errors
3. Verify openssl is installed: `openssl version`

## Files Modified

- `temp_cmd.sh` - Added automatic certificate generation
- `generate_node_certs.sh` - Standalone certificate generation script
- `src/init/http_handler.cc` - Certificate path discovery logic

## Related Documentation

- `HTTPS_MIGRATION.md` - HTTP to HTTPS migration guide
- `HTTPS_SERVER_FIX.md` - HTTPS server troubleshooting
- `HTTPS_CLIENT_UPDATE.md` - Python client HTTPS update
