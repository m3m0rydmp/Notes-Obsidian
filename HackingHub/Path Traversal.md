It is a security vulnerability that allows an attacker to access files and directories stored outside of the intended web root folder. The attack occurs when an application uses unsanitized user input to construct a file path. By injecting special character sequences like `../` in Unix/Linux or `..\` in Windows an attack can "climb" up the directory hierarchy.

#### Traditional Website
In a traditional website if a user interacts with an application for example: `https://app.target.com/customer?id=1234` we make that request from the browser then to the website, which is the **frontend**. The website then communicates to the database which is in the **backend** and fetches all the relevant information it needs to make that page pass it back to the web server. Then the web server creates the whole page as html and passes it back to the browser which then gets render and view it as a whole page.

#### Modern Website
Websites like **Single Page Application (SPAs)** revolutionize the approach by loading once and then dynamically updating content:
```text
Initial Load:
┌─────────────┐         ┌─────────────┐
│   Browser   │────────>│   Server    │
│             │  Request│             │
│             │<────────│             │
└─────────────┘  HTML + └─────────────┘
                 JS + CSS
                 (App Shell)

Subsequent Navigation:
┌─────────────┐         ┌─────────────┐
│   Browser   │────────>│   API       │
│  (JS runs)  │  Fetch  │   Server    │
│             │<────────│             │
└─────────────┘  JSON   └─────────────┘
      │              
      └──> Updates DOM
           (No page reload!)
```
Characteristics of SPAs:
1. **Single HTML Page**: Only one initial HTML document is loaded
2. **JavaScript-Driven**: Client-side JavaScript handles routing and rendering
3. **Dynamic Updates**: Content changes without full page reloads
4. **API Communication**: Data fetched via AJAX/Fetch as JSON
5. **Fast Interactions**: Instant navigation after initial load

In traditional server-side apps, path traversal `(../../etc/passwd)` is well-known. But SPAs introduce client-side variants:
```text
Normal SPA Flow:
┌─────────────────┐
│   User clicks   │
│  "/profile/123" │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Client-Side Router            │
│   Validates & Routes            │
└────────┬────────────────────────┘
         │
         ▼
┌───���─────────────────────────────┐
│   Fetch: /api/user/123          │
└────────┬────────────────────────┘
         │
         ▼
    [User Data]


Path Traversal Attack:
┌─────────────────────────────────┐
│   Attacker manipulates URL:     │
│   "/profile/../../admin/config" │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Vulnerable Router             │
│   ❌ No validation!             │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│   Fetch: /api/admin/config      │
│   (Unauthorized access!)        │
└────────┬────────────────────────┘
         │
         ▼
    [Sensitive Data Leaked! 🚨]
```

## Basic Examples of Path Traversal
Threat actors often look for input fields that is reflected in URL like `?profile=` to inject the payload, as well as API calls. An attack vector example would be:
* **Input Field**: `../../config/database`
* **API Call**: `/api/docs/../../config/database`

For the payloads they often come as:
```
Normal use:     user-docs/report.pdf
Attack 1:       ../../etc/passwd
Attack 2:       ../admin/users.json
Attack 3:       ../../config/.env
Attack 4:       ..%2F..%2Fsecrets.txt (URL encoded)
Attack 5:       ....//....//system/config
```