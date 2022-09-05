# SSHDog

SSHDog is your go-anywhere lightweight SSH server.  Written in Go, it aims
to be a portable SSH server that you can drop on a system and use for remote
access without any additional configuration.

Useful for:

* Tech support
* Backup SSHD
* Authenticated remote bind shells

Supported features:

* Windows & Linux
* Configure port, host key, authorized keys
* Pubkey authentication (no passwords)
* Port forwarding
* SCP (but no SFTP support)

Example usage:

```
% go build ./cmd/sshdog
% ssh-keygen -t rsa -b 2048 -N '' -f config/ssh_host_rsa_key
% echo 2222 > config/port
% cp ~/.ssh/id_rsa.pub config/authorized_keys
% rice append --exec sshdog
% ./sshdog
[DEBUG] Adding hostkey file: ssh_host_rsa_key
[DEBUG] Adding authorized_keys.
[DEBUG] Listening on :2222
[DEBUG] Waiting for shutdown.
[DEBUG] select...
```

Author: David Tomaschik <dwt@google.com>

*This is not a Google product, merely code that happens to be owned by Google.*



