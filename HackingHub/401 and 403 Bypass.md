HTTP status codes **401 (Unauthorized)** and **403 (Forbidden)** that prevents unauthorized users to gain access on a specific endpoint in a web application. **401** occurs when a request lacks valid authentication credentials, while **403** occurs when the server understands the request but refuses o authorize it.

Here are some common bypass techniques and what their backend looks like:

#### Case Sensitive
Using case-sensitive comparison instead of case-insensitive. Basically, something like change one letter from lowercase to uppercase or something.
Example an endpoint like: `/app/admin` -> `/app/admiN`
```php
function caseBypass() {
    $blockedPaths = ['/admin', '/secret', '/flag'];
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // VULNERABLE: Strict comparison doesn't normalize case
    if (in_array($requestUri, $blockedPaths)) {
        http_response_code(403);
        die("Forbidden");
    }
}
```
**Bypass**: `/admiN` passes because it's not in the blocklist
**Fix**: Sample mitigation would be
```php
strtolower() for comparison
if (in_array(strtolower($requestUri), $blockedPaths))
```

#### Extra Directories
Blacklist check before path normalization, appending an extra `/` which is an extra directory
Example: `/app/flag` -> `/app//flag`
```php
function doubleSlashBypass() {
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // VULNERABLE: Check happens before normalization
    if (strpos($requestUri, '/app/flag') !== false) {
        http_response_code(403);
        die("Forbidden");
    }
    
    // Later in the code, path gets normalized
    $normalizedPath = preg_replace('#/+#', '/', $requestUri); // //app//flag -> /app/flag
}
```
**Bypass**: `/app//flag` passes the blacklist check, then gets normalized to `/app/flag` and serves the file
**Fix**: Normalize BEFORE checking

#### Encoding
URL decoding happens AFTER security check, a character like `..` or `/`
Example: `/app/flag` -> `/app%2Fflag`
Execute the payload using `curl` like: `curl 'https://ctfhub.io/..%2Fapp/flag'`
```php
function urlEncodedBypass() {
    $requestUri = $_SERVER['REQUEST_URI']; // %2F is NOT decoded yet
    
    // VULNERABLE: Checking raw URI
    if (strpos($requestUri, '/app/flag') !== false) {
        http_response_code(403);
        die("Forbidden");
    }
    
    // Web server or framework decodes %2F -> / later
    $decodedPath = urldecode($requestUri); // /app/%2Fflag -> /app/flag
}
```
**Bypass**: `/app/%2Fflag` passes check, then gets decoded to `/app/flag`
**Fix**: Decode before checking or use `$_SERVER['PATH_INFO]`

#### Double URL Encoding
Double decoding (WAF decodes once, app decodes again)
Example: `/app/flag` -> `/app%252Fflag`
Execute the payload using `curl` like: `curl 'https://ctfhub.io/..%252Fapp/flag'`
```php
function doubleUrlEncodedBypass() {
    // First layer: WAF/Proxy does one decode
    $firstDecode = urldecode('/app%252Fflag'); // -> /app%2Fflag
    
    // VULNERABLE: WAF checks /app%2Fflag (looks safe)
    if (strpos($firstDecode, '/app/flag') !== false) {
        http_response_code(403);
        die("Forbidden - WAF");
    }
    
    // Second layer: Application does another decode
    $secondDecode = urldecode($firstDecode); // -> /app/flag
    
    // BYPASS: %252F becomes %2F after first decode (passes WAF)
    //         Then becomes / after second decode (reaches protected resource)
    
    // FIX: Only decode once, or check after all decoding
}
```
**Bypass**: `%252F` becomes `%2F` after first decode (passes WAF). Then becomes / after second decode (reaches protected resources)
**Fix**: Only decode once, or check after all decoding

#### Path Traversal With Non-Existent Directory
Blacklist check before path traversal resolution
Example: `/app/flag` -> `/status/..%2Fapp/flag`
Execute the payload using `curl` like: `curl 'https://ctfhub.io/v1/..%252Fapp/flag'`
```php
function pathTraversalBypass() {
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // VULNERABLE: Checking literal path before resolving ../
    if (strpos($requestUri, '/app/flag') !== false) {
        http_response_code(403);
        die("Forbidden");
    }
    
    // Later: URL decode happens
    $decoded = urldecode($requestUri); // /status/..%2Fapp/flag -> /status/../app/flag
    
    // Then: Path normalization resolves ../
    $resolved = realpath($decoded); // /status/../app/flag -> /app/flag
}
```
**Bypass**: The `v1` endpoint is non-existent, and is still essential but will not be read by the web application. As the `..` payload cancels everything before it, so it will be read `/app/flag`
**Fix**: Resolve paths BEFORE checking, or use `realpath()` early

#### Double Encoded Path Traversal
This is a combined technique from [Double URL Encoding](#Double%20URL%20Encoding) and [Path Traversal With Non-Existent Directory](#Path%20Traversal%20With%20Non-Existent%20Directory) 
```php
function doubleEncodedPathTraversal() {
    // Same as #5 but with double encoding
    // %252F -> %2F (first decode) -> / (second decode)
    // Then path normalization resolves /status/../app/flag -> /app/flag
}
```

#### Trailing Backslash
Different parsing between security check and file handler
Example: `/app/flag` -> `/app/flag\`
```php
function trailingBackslashBypass() {
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // VULNERABLE: Exact match check
    if ($requestUri === '/app/flag') {
        http_response_code(403);
        die("Forbidden");
    }
    
    // File handler might strip trailing slashes/backslashes
    $cleanPath = rtrim($requestUri, '\\/'); // /app/flag\ -> /app/flag
}
```
**Bypass**: `/app/flag\` !== `/app/flag` passes check. But file handler treats them the same.
NOTE: The effectiveness depends on OS and web server. On **Windows** treats `\` similar to `/`. Some web servers auto-normalize trailing characters
**Fix**: Normalize paths before comparison

#### HTTP Method Bypass
Access control only on GET requests
Example: `GET /app/flag` -> `POST /app/flag`
A `curl` must be used, or `BurpSuite` or any interceptor of your choice to change the Method request
```php
function methodBypass() {
    $requestUri = $_SERVER['REQUEST_URI'];
    $method = $_SERVER['REQUEST_METHOD'];
    
    // VULNERABLE: Only blocking GET requests
    if ($method === 'GET' && $requestUri === '/app/flag') {
        http_response_code(403);
        die("Forbidden");
    }
    
    // Application serves the same content for POST
    if ($requestUri === '/app/flag') {
        // Serves flag for both GET and POST
        echo file_get_contents('/app/flag.txt');
    }
}
```
**Bypass**: Change `GET` to `POST`  security check doesn't apply
**Fix**: Apply access control regardless of HTTP method, or explicitly reject unwanted methods

#### X-Forwarded-For Header Bypass
Trusting X-Forwarded-For header for IP-based access control
Example, add this in your headers: `X-Forwarded-For: 127.0.0.1`
```php
function headerBypass() {
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // VULNERABLE: Using X-Forwarded-For without validation
    $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
    
    // Access control based on IP
    if ($requestUri === '/app/flag') {
        if ($clientIp !== '127.0.0.1') {
            http_response_code(403);
            die("Forbidden - Admin access only");
        }
        echo "FLAG{secret}";
    }
}
```
**Bypass**: Attacker adds header `X-Forwarded-For: 127.0.0.1`, application thinks request is from localhost. The `X-Forwarded-For` is set by proxies to track original client IP but, it's just an HTTP header anyone can see it. It app trusts it blindly, attacker can spoof their IP.
**Fix**: Don't trust `X-Forwarded-For` unless behind a trusted proxy. Use `REMOTE_ADDR` which can't be spoofed (set by web server). If using proxy, validate the proxy chain.

#### Sample Main Router
```php
$path = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

// Example vulnerable routing
if (stripos($path, 'admin') !== false) {
    caseBypass();
    echo "Admin panel accessed!";
}

if (strpos($path, 'flag') !== false) {
    // Multiple bypass vulnerabilities present
    doubleSlashBypass();
    urlEncodedBypass();
    pathTraversalBypass();
    methodBypass();
    headerBypass();
}
?>
```