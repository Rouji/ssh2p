# ssh to POST
SSH server that doesn't require any auth and does nothing but POST received data (stdin) to an HTTP(S) URL.  
Useful for giving existing pastebin-like sites a way of pasting via SSH. 

# Usage:
```
./ssh2p
Usage: ./ssh2p [-l listen_ip] [-p listen_port] [-f form_field] [-n filename] [-r rsa_key] upstream_url
```

You'll also need an RSA key. You can generate one using `ssh-keygen -t rsa -f id_rsa`

# Building:
```bash
meson build
ninja -C build
```
