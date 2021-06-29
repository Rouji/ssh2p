# SSH to POST
SSH server that doesn't require any auth and does nothing but POST received data (stdin) to an HTTP(S) URL.  
Useful for giving existing pastebin-like sites a way of pasting via SSH. 

# Building
```bash
meson build
ninja -C build

#optionally
cd build; meson install
```

# Running this on the Server-Side
Hopefully somewhat self-explanatory: 
```
./ssh2p
Usage: ./ssh2p [OPTIONS] upstream_url

OPTIONS:
  -l <listen_ip>    IP to listen on (default: 0.0.0.0)
  -p <listen_port>  port to listen on (default: 22)
  -f <form_field>   name of the HTML form field for the uploaded file (default: file)
  -n <filename>     name of the uploaded file (default: file)
  -t <timeout>      SSH receive timeout in seconds (default: 5)
  -r <rsa_key>      RSA ID file (default: id_rsa)
```
You can generate an RSA key using `ssh-keygen -t rsa -f id_rsa`  

The `X-Forwarded-For` is set to the client's IP in the POST request to upstream, so you can do your logging in your web server. The stdout/err of this program is more for debugging purposes than anything else. 

# Client-Side Usage
If you've got this and [some file host](https://github.com/Rouji/single_php_filehost) running on `example.com`:  
```bash
# echo this is some text | ssh example.com
Pseudo-terminal will not be allocated because stdin is not a terminal.
https://example.com/fT-3.txt
Connection to example.com closed by remote host.
```
The messages about the pseudo-terminal and closed connection (while annoying) are on stderr and don't impact scripting stuff. `ssh -q` gets rid of the former but not the latter.  
`ssh2p` will send an exit status of 0 if everything went OK and it got a 200 back from the upstream, so you can do `ssh example.com && echo "success!"` etc.  
Error messages are sent through, and will come out of `ssh` as, stderr.  

# Privacy
Apart from passing the client IP on to the upstream, this doesn't do any data hoovering.  
*Could* it log usernames, public keys, passwords? Absolutely. But it doesn't. There's nothing in the code to do that.  
Should you trust me or anyone else running this to not have added that code? Nope.
