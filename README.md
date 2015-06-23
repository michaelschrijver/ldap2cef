# ldap2cef
A script which rsyslog (or any other processor) sends its data to.
*ldap2cef* will read from stdin and process lines, and then send it to OUTFILE

## Dependencies
* This needs `repoze.lru`, Least Recently Used lib for storing connections, `sudo pip3 install repoze.lru`
* Rsyslog7 `echo -e 'install rsyslog7 \n erase rsyslog \n run'| sudo yum shell`

## Rsyslog config
```
if $programname == "slapd" then
        action(type = "omprog" binary="/usr/bin/python3.4 -u /path/to/ldap2cef.py" template="RSYSLOG_TraditionalFileFormat")
```

## Hints
* Change the OUTFILE and create parent dirs, with correct perms
* Set up logrotate for the OUTFILE

## History
Originally an idea by [mobjack](https://github.com/mobjack/LDAP2CEF), edited by [michaelschrijver](https://github.com/michaelschrijver/ldap2cef) and [karloluiten](https://github.com/karloluiten/ldap2cef)

:wq
