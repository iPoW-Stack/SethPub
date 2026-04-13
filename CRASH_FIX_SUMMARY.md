# HTTPS Server Crash Fix Summary

## Problem
The HTTPS server was crashing with `std::terminate()` when handling requests. The stack trace showed:
```
#7  0x000079a4968a5a55 in std::terminate()
#8  uWS::HttpContext<true>::init()::{lambda...}
```

## Root Causes

### 1. Unhandled Exceptions in Lambda Functions
uWebSockets requires all exceptions to be caught within lambda handlers. Any uncaught exception causes `std::terminate()` to be called, crashing the application.

### 2. Duplicate Endpoint Definitions
The code had duplicate endpoint definitions due to a merge error, causing undefined behavior.

### 3. Missing Response Abort Handling
When a client disconnects, the response object becomes invalid, but the code continued to access it.

## Solution

### 1. Added Safe Handler Wrapper
Created a `safeHandler` lambda that wraps all endpoint handlers with:
- **Exception protection**: try-catch blocks for all exceptions
- **Abort handling**: `onAborted()` callback to track disconnections
- **Response tracking**: Prevents writing to already-responded connections

```cpp
auto safeHandler = [](auto handler, const char* endpoint) {
    return [handler, endpoint](auto *res, auto *req) {
        auto body = std::make_shared<std::string>();
        auto responded = std::make_shared<bool>(false);
        
        res->onAborted([responded]() {
            *responded = true;
        });
        
        res->onData([res, req, body, handler, endpoint, responded](...) {
            if (*responded) return;  // Client disconnected
            
            try {
                // Handle request
            } catch (const std::exception& e) {
                SETH_ERROR("Exception in %s: %s", endpoint, e.what());
                // Send error response
            } catch (...) {
                SETH_ERROR("Unknown exception in %s", endpoint);
                // Send error response
            }
        });
    };
};
```

### 2. Simplified Endpoint Registration
All endpoints now use the safe handler:
```cpp
.post("/transaction", safeHandler(HttpTransaction, "/transaction"))
.post("/query_account", safeHandler(QueryAccount, "/query_account"))
// ... all other endpoints
```

### 3. Removed Duplicate Code
Eliminated all duplicate endpoint definitions that were causing conflicts.

### 4. Changed to IPv4 Listening
Changed from IPv6 (`:::`) to IPv4 (`0.0.0.0`):
```cpp
.listen("0.0.0.0", http_port_, callback)
```

## Benefits

1. **Crash Prevention**: All exceptions are caught and logged
2. **Better Error Handling**: Clients receive proper 500 error responses
3. **Disconnect Safety**: No crashes when clients disconnect mid-request
4. **Cleaner Code**: Single handler wrapper instead of repeated try-catch blocks
5. **Better Debugging**: All exceptions are logged with endpoint names

## Testing

### Verify Server Starts
```bash
netstat -nlp | grep 23001
```

Expected output:
```
tcp  0  0  0.0.0.0:23001  0.0.0.0:*  LISTEN  <pid>/seth
```

### Test Request Handling
```bash
curl -k -X POST https://127.0.0.1:23001/query_account \
  -d "address=0123456789abcdef0123456789abcdef01234567"
```

### Test Exception Handling
Send malformed requests to verify graceful error handling:
```bash
curl -k -X POST https://127.0.0.1:23001/query_account -d "invalid_data"
```

Should return 500 error instead of crashing.

### Monitor Logs
```bash
tail -f /root/seths/s3_1/log/seth.log | grep -E "Exception|ERROR"
```

## Files Modified

- `src/init/http_handler.cc`:
  - Added `safeHandler` wrapper function
  - Wrapped all 19 endpoints with exception protection
  - Removed duplicate endpoint definitions
  - Changed listen address to "0.0.0.0"

## Related Issues Fixed

1. ✅ Server crashes on client disconnect
2. ✅ Server crashes on malformed requests
3. ✅ Server crashes on internal exceptions
4. ✅ IPv6 listening instead of IPv4
5. ✅ Duplicate endpoint definitions

## Future Improvements

1. Add request timeout handling
2. Add request size limits
3. Add rate limiting per endpoint
4. Add metrics/monitoring for exceptions
5. Consider using connection pooling
