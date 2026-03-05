APIs (Application Programming Interfaces) enable software systems and applications to communicate and share data. API testing is important as vulnerabilities in APIs may undermine core aspects of a website's confidentiality, integrity, and availability.

All dynamic websites are composed of APIs, so classic web vulnerabilities like SQL injection could be classed as API testing. In this topic, we'll learn you to test APIs that aren't fully used by website front-end, with a focus on RESTful and JSON APIs. We'll also learn how to test for server-side parameter pollution vulnerabilities that may impact internal APIs.

## API Recon
To start API testing, you first need to find out as much information about the API as possible, to discover its attack surface.

To begin, you should identify API endpoints. These are locations where an API receives requests about a specific resource on its server. For example, consider the following `GET` request:
```http
GET /api/books HTTP/1.1
Host: example.com
```
The API endpoint for this request is `/api/books`. This results in an interaction with the API to retrieve a list of books from a library. Another API endpoint might be for example, `/api/books/mystery`, which would retrieve a list of mystery books.

Once you have identified the endpoints, you need to determine how to interact with them. This enables you to construct valid HTTP requests to test the API. For example, you should find out information about the following:
* The input data the API processes, including both compulsory and optional parameters.
* The types of requests the API accepts, including supported HTTP methods and media formats.
* Rate limits and authentication mechanisms.

## API Documentation
APIs are usually documented so that developers know how to use and integrate with them. Documentation can be in both human-readable and machine-readable forms. Human-readable documentation is designed for developers to understand how to use the PAI. It may include detailed explanations, examples, and usage scenarios. Machine-readable documentation is designed to be processed by software for automating tasks like API integration and validation. It's written in structured formats like JSON or XML.

API documentation is often publicly available, particularly if the API is intended for use by external developers. If this is the case, always start your recon by reviewing the documentaiton.

## Discovering API Documentation
Even if API documentation isn't openly available, you may still be able to access it by browsing applications that use the API

To do this, you can use Burp Scanner to crawl the API. You can also browse applications manually using Burp's browser. Look for endpoints that may refer to API documentation, for example:
* `/api`
* `/swagger/index.html`
* `/openapi.json`
If you identify an endpoint for a resource, make sure to investigate the base path. For example, if you identify the resource endpoint `/api/swagger/v1/users/123`, then you should investigate the following paths:
* `/api/swagger/v1`
* `/api/swagger`
* `/api`
You can also use a list of common paths to find documentation using intruder
#### Using Machine-Readable Documentation
You can use a range of automated tools to analyse any machine-readable API documentation that you find.

You can use Burp Scanner to crawl and audit OpenAPI documentation, or any other documentation in JSON or YAML format. You can also parse OpenAPI documentation using the OpenAPI Parser BApp.

You may also be able to use a specialized tool to test the documented endpoints, such as Postman or SoapUI.

## Identifying API Endpoints
You can also gather a lot of information by browsing applications that use the API. This is often worth doing even if you have access to API documentation, as sometimes documentation may be inaccurate or out of date.

You can use Burp Scanner to crawl the application, then manually investigate interesting attack surface using Burp's browser.

While browsing the application, look for patterns that suggest API endpoints in the URL structure, such as `/api/`. Also look out for JavaScript files. These can contain references to API endpoints that you haven't triggered directly via the web browser. Burp Scanner automatically extracts some endpoints during crawls, but for a more heavyweight extraction, use the JS Link Finder BApp. You can also manually review JavaScript files in Burp.

#### Interacting with API Endpoints
Once you've identified API endpoints, interact with them using Burp Repeater and Burp Intruder. This enables you to observe the API's behaviour and discover additional attack surface. For example, you could investigate how the API responds to changing the HTTP method and media type. As you interact with the API endpoints, review error messages and other responses closely. Sometimes these include information that you can use to construct a valid HTTP request.

##### Identifying Supported HTTP Methods
The HTTP method specifies the action to be performed on a resource. For example:
* `GET` - Retrieves data from a resource
* `PATH` - Applies partial changes to a resource
* `OPTIONS` - Retrieves information on the types of request methods that can be used on a resource.
An API endpoint may support different HTTP methods. It's therefore important to test all potential methods when you're investigating API endpoints. This may enable you to identify additional endpoint functionality, opening up more attack surface.

For example, the endpoint `/api/tasks` may support the following methods:
* `GET /api/tasks` - Retrieves a list of tasks
* `POST /api/tasks` - Creates a new task
* `DELETE /api/tasks` - Delete a task
You can use the built-in **HTTP verbs** list in Burp Intruder to automatically cycle through a range of methods.

#### Identifying Supported Content Types
API endpoints often expect data in a specific format. They may therefore behave differently depending on the content type of the data provided in a request. Changing the content type may enable you to:
* Trigger errors that disclose useful information
* Bypass flawed defenses
* Take advantage of differences in processing logic. For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML
To change the content type, modify the `Content-Type` header, then reformat the request body accordingly. You can use the Content type converter BApp to automatically convert data submitted within requests between XML and JSON

#### Using Intruder to Find Hidden Endpoints
Once you have identified some initial API endpoints, you can use Intruder to uncover hidden endpoints. For example, consider a scenario where you have identified the following API endpoint for updating user information:
`PUT /api/user/update`
To identify hidden endpoints, you could use Burp Intruder to find other resources with the same structure. For example, you could add a payload to the `/update` position of the pan with a list of other common functions, such as `delete` and `add`.

When looking for hidden endpoints, use wordlists based on common API naming conventions and industry terms. Make sure you also include terms that are relevant to the application, based on your initial recon.

## Finding Hidden Parameters
When you're going API recon, you may find undocumented parameters that the API supports. You can attempt to use the change the application's behaviour. Burp includes numerous tools that can help you identify hidden parameters:
* Burp Intruder enables you to automatically discover hidden parameters, using a wordlist of common parameter names to replace existing parameters or add new parameters. Make sure you also include names that are relevant to the application, based on your initial recon.
* The Param miner BApp enables you to automatically guess 65536 param names per request. Param mine automatically guesses names that are relevant to the application, based on information taken from the scope.
* The Content discovery tool enables you to discover content that isn't linked from visible content that you can browse to, including parameters.

## Mass Assignment Vulnerabilities
Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. It occurs when software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be process by the developer.

#### Identifying Hidden Parameters
Since mass assignment creates parameters from object fields, you can often identify these hidden parameters by manually examining objects returned by the API.

For example, consider a `PATCH /api/users/` request, which enables users to updated their username and email, and includes the following JSON:
```JSON
{ "username": "wiener", "email": "wiener@example.com", }
```
A concurrent `GET /api/users/123` request returns the following JSON:
```json
{ "id": 123, "name": "John Doe", "email": "john@example.com", "isAdmin": "false" }
```
This may indicate that the hidden `id` and `isAdmin` parameters are bound to the internal user object, alongside the updated username and email parameters.

##### Testing mass assignment vulnerabilities
To test whether you can modify the enumerated `isAdmin` parameter value, add it to the `PATCH` request:
```json
{ "username": "wiener", "email": "wiener@example.com", "isAdmin": false, }
```
In addition, send a `PATCH` request with an invalid `isAdmin` parameter value:
```json
{ "username": "wiener", "email": "wiener@example.com", "isAdmin": "foo", }
```

If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user.
You can then send a `PATCH` request with the `isAdmin` parameter value set to `true`, to try and exploit the vulnerability:
```JSON
{ "username": "wiener", "email": "wiener@example.com", "isAdmin": true, }
```
If the `isAdmin` value in the request is bound to the user object without adequate validation and sanitization, the user `wiener` may be incorrectly granted admin privileges. To determine whether this is the case, browse the application as `wiener` to see whether you can access admin functionality.

## Preventing Vulnerabilities in APIs
When designing APIs, make sure that security is a consideration from the beginning. In particular, make sure that you:
* Secure your documentation if you don't intend your API to be publicly accessible.
* Ensure your documentation is kept up to date so that legitimate testers have full visibility of the API's attack surface.
* Apply an allowlist of permitted HTTP methods.
* Validate that the content type is expected for each request or response.
* Use generic error messages to avoid giving away information that may be useful for an attacker.
* Use protective measures on all versions of your API, not just the current production version.
To prevent mass assignment vulnerabilities, allowlist the properties that can be updated by the user, and blocklist sensitive properties that shouldn't be updated by the user.

## Exploiting an API Endpoint Using Documentation
[LABS: Exploiting an API endpoint using documentation](https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation)
This lab leverage the opportunity that an attacker could use the documentation of the API to interact and exploit it. The documentation of an API is an information disclosure to an attacker because it tells them how the API should behave and what request payload such as `{ "email": String}` does the endpoint (like `/api/users/`) is taking.

To solve the lab, login with `wiener:peter` and then change its email after a successful login. In the HTTP history in BurpSuite, you will notice there is a `PATCH /api/user/wiener`. You can test how it reacts by removing one endpoint at a time like in `/api/user` it returns an error, but with `/api` only it redirects you to the documentation. If you copy its URL and paste it in the browser, the documentation is interactive which has a GET, PATCH, and DELETE for `/api/user` it also reveals what request payload the `PATCH` verb is taking which is `{"email": String}`. It also reveals what endpoint is it taking like `/user/[username: String]`, this means that the endpoint after `/user` is taking a string like **Wiener**, **Carlos**, **John**, etc. You can proceed to interact with the `DELETE` verb and delete the user named Carlos.

## Exploiting Server-Side Parameter Pollution in a Query String
[LABS: Exploiting server-side parameter pollution in a query string](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string)
The goal of the lab is to trick the server-side to return the `reset_token` for the user **administrator** then use that `reset_token` to pass on the parameter in `/forgot-password` to change the password of the administrator. Do not login with any user but instead head directly to the forgot password then put the name of administrator. In BurpSuite HTTP history, there is a `POST /forgot-password` endpoint, the request payload is a `csrf` and `username`. If we try to put a wrong username, it returns an error. Try to append a `#` with the username administrator but URL encode it like `administrator%23`, it returns an error saying `Field not specified` this hints that the server includes an additional parameter called `field` which has been removed by `#`

Remove the truncation `#` then add a `field` parameter, put any value on the `field` parameter then append the truncation `#` but pass it as a URL which would be `username=administrator%26field=xxx%23` where `%26 -> &` and `%23 -> #`. Send the request and the server will respond with `Invalid field`, this hints that the server recognize the parameter `field` but it has the wrong value. So we need to brute force its value using the **Server-Side Variable Names** in BurpSuite Intruder. When the attack has started, there are 2 parameters that will return a `200` status code, it will be `username` and `email`. Now, put the value `email` in the `field` parameter, then send the request. The server will have a `200` response returning the following:
```http
HTTP/2 200 OK

Content-Type: application/json; charset=utf-8

X-Frame-Options: SAMEORIGIN

Content-Length: 49



{"result":"*****@normal-user.net","type":"email"}
```
This hints us that `email` is a valid field type. Since we're trying to make our way in the `/forgot-password` endpoint, we need to look at its JavaScript on what is its logic. We can see a function in JavaScript that the `/forgot-password` requires a `reset_token` in order to change the password of the user. So in the `POST /forgot-password` with the username of **administrator** we need to change the value of `field` from `email` to `reset_token` while keeping the truncation at the end. The server will respond with `200` with the reset token of the user **administrator**. Copy that token, and navigate to `/forgot-password` in the browser. Then pass a parameter in the URL with `/forgot-password?reset_token=[reset token]` this will take you to the page where you can reset the password of the user administrator. Login then delete the user Carlos to solve the lab.

The server likely has a backend with an example, not really the actual:
```SQL
SELECT [field] FROM users WHERE username = '[username]'
```
By injecting `%26field=reset_token%23`, we are essentially "rewriting" the server's intended logic. As `%23` which is `#` a truncator, tells the backend to ignore the rest of the original intended string. There is no logical explanation why we should pass `reset_token` as the value in `field` parameter. This is more of a hacker's intuition since we knew that passing the `email` value is accepted by the server, we could think of something else such as "Is there any other value that I can pass aside from email?". A friend of mine that is good in API hacking always tells me to read the JavaScript of the website, because we might get lucky if everything is in client-side and the API is dependent on the backend.

## Finding and Exploiting an Unused API Endpoint
[LABS: Finding and exploiting an unused API endpoint](https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint)
The goal of this lab is to make use of the `PATCH` HTTP request method, this allows us to change the price of the product. When selecting a product, a JSON response is revealed with the parameters `price` and `message`. 

The reconnaissance step for this is to try and select any product. In the HTTP history an endpoint with `/api/products/1/price` is queried if you view a product. To test this, we can send an `OPTIONS` request method for us to know what kind of methods are accepted. If we send the request, it will return an error but will tell us on the response header that the allowed methods are `GET` and `PATCH`. This hints that if we use `PATCH` on this endpoint, we can change the value of the parameters. 

So we go back to the "Lightweight Leather Jacket", since our store credit is $0, we will try to use the `PATCH` method to change the price of the product. Click on the product, then inspect the HTTP history in BurpSuite, send the request to Repeater then edit the method from `GET` to `PATCH` if we try to send this request there will be an error. That's because it's missing a request body, so we try to send an empty request with `{}`. There's still an error because it's missing a parameter. As we noted earlier that when we do a `GET` request the parameters of the product are `price` and `message`. So put a `price` parameter in the request body with `{"price": 0}` with the `PATCH` method, this allows us to modify the price of the product. Send the request, and go back to the browser and refresh the page, now you will be able to add the product to card then buy the product for free.

## Exploiting a Mass Assignment Vulnerability
[LAB: Exploiting a mass assignment vulnerability](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability)
The goal of this lab is to find an API endpoint with responses and modify that parameter so that. First, we need to login with the account `wiener:peter`. The thinking here is that, if we find an API response on the website, can we use those parameter in response by modifying the expected value. In the endpoint `/api/checkout` where we would need to send a `POST` request to buy a product. There is an API response with the following.
```JSON
{ "chosen_discount":{ "percentage":0 }, "chosen_products":[ { "product_id":"1", "quantity":1 } ] }
```
If we attempt to remove the `chosen_discount` parameter, it will still be accepted. However, changing its value from integer to a string will respond an error. At this point we can experiment on the parameters to change its values. Mass assignment occurs when an application automatically binds user-supplied input to internal program objects or variables without proper validation or restrictions. Change the request method for the endpoint `/api/Checkout` from `GET` to `POST`. Then modify the `percentage` parameter under the `chosen_discount` parameter to 100 since this parameter only accepts integer value. Send the `POST` request then a status of `201 Created` will be in the response. Go to your browser, refresh the page on the cart page and the lab will be solved.