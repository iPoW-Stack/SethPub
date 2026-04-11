# HTTPS Server Fix Summary

## Problem
HTTPS server (port 23001) was not starting and listening. The issue was caused by:
1. Missing SSL certificate files in the node runtime directories
2. Incorrect listen() call parameters for uWebSockets

## Fixes Applied

### 1. Fixed listen() Call
Changed from:
```cpp
.listen(http_ip_, http_port_, callback)
```

To:
```cpp
.listen(http_ip_ == "0.0.0.0" ? "" : http_ip_, http_port_, callback)
```

**Reason**: uWebSockets expects an empty string (not "0.0.0.0") to listen on all interfaces.

### 2. Added Certificate File Discovery
Modified `HttpHandler::Init()` to search for certificate files in multiple locations:
- Current directory: `server-cert.pem`, `server-key.pem`
- Parent directory: `../server-cert.pem`, `../server-key.pem`
- Grandparent directory: `../../server-cert.pem`, `../../server-key.pem`
- Absolute path: `/root/seth/server-cert.pem`, `/root/seth/server-key.pem`

This allows the server to find certificates even when running from different directories.

### 3. Added Error Logging
Added detailed logging to help diagnose certificate loading issues:
```cpp
SETH_INFO("Found certificate file: %s", path.c_str());
SETH_ERROR("Certificate or key file not found! cert: %s, key: %s", ...);
```

## Deployment Steps

### Option 1: Copy Certificates to Node Directories
Run the provided script to copy certificates to all node directories:
```bash
cd /root/seth
./copy_certs_to_nodes.sh
```

### Option 2: Use Symbolic Links
Create symbolic links in each node directory:
```bash
cd /root/seths/s3_1
ln -s /root/seth/server-cert.pem .
ln -s /root/seth/server-key.pem .
```

### Option 3: Rebuild and Restart
The code now automatically searches parent directories, so just rebuild and restart:
```bash
cd /root/seth
./build.sh
# Restart your nodes
```

## Verification

After restarting the node, verify HTTPS is listening:
```bash
netstat -nlp | grep 23001
```

Expected output:
```
tcp  0  0  0.0.0.0:23001  0.0.0.0:*  LISTEN  <pid>/seth
```

Test with curl:
```bash
curl -k -X POST https://127.0.0.1:23001/query_account -d "address=<some_address>"
```

Or use the Python client (already updated to use HTTPS):
```bash
cd /root/seth/clipy
python3 seth3.py
```

## Files Modified
- `src/init/http_handler.cc` - Fixed listen() call and added certificate discovery
- `copy_certs_to_nodes.sh` - Script to copy certificates to node directories
- `clipy/seth_sdk.py` - Already updated to use HTTPS (previous fix)

## Security Notes
- The code searches multiple paths for convenience in development
- For production, use absolute paths or environment variables
- Ensure certificate files have proper permissions (cert: 644, key: 600)
- Consider using proper CA-signed certificates for production
