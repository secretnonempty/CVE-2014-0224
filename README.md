OPENSSL CVE-2014-0224 MITM exploit demo.<br>
<br>
Author : @bluerust<br>
Blog   : http://hi.baidu.com/bluerust/item/bf2ab031bbadcf09cfb9fe41<br>
Ver    : 1.1<br>
Desc   :<br>
Only for openssl 1.0.1*, only tested for cipher RC4-SHA.<br>
 a. server<br>
  openssl s_server -debug -accept 443 -cert server.crt -certform PEM -key server.key -cipher RC4-SHA<br>
  we don't want to discuss how to generate the certificate in here.<br>
 b. client<br>
  openssl s_client -connect 127.0.0.1:9999 -debug -cipher RC4-SHA<br>
 c. mitm proxy<br>
  go run proxy_all.go -host=127.0.0.1 -port 443 -listen_port=9999<br>
<br>
--------------------------<br>
 References:<br>
 [1] Early ChangeCipherSpec Attack (05 Jun 2014)<br>
 https://www.imperialviolet.org/2014/06/05/earlyccs.html <br>
 [2] SSL/TLS MITM vulnerability (CVE-2014-0224)<br>
 http://www.openssl.org/news/secadv_20140605.txt<br>
 [3] How I discovered CCS Injection Vulnerability (CVE-2014-0224)<br>
 http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html<br>

