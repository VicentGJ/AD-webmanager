# Introduction
This project is a web interface for Samba4 made using Flask and python-ldap.

It's using the connecting user's own credentials to connect to the
directory and allow a variety of operations.

The goal is to be able to do most common directory operations directly
through this web interface rather than have to rely on command tools or
Windows interfaces.

# History
Around 3 years ago, the Ubuntu flavor for education, Edubuntu, started
working on a server edition, using containers for the various services
commonly used by school districts and using Samba4 as the directory.

Due to limited spare time by the main developers, this project slowly
died but the web inteface developped to manage the Samba4 server still
evolved and over the years, got a bunch of bugfixes and improvements.

As a result, it was decided that this should be turned into its own
project, outside of the scope of the Edubuntu project and be made widely
available.

# Dependencies
 * python
 * python-dnspython
 * python-flask
 * python-flaskext.wtf,
 * python-ldap
 * python-wtforms

# Using

 * Copy manager.cfg.example to manager.cfg
 * Put a random string in SECRET\_KEY
 * Set LDAP\_DOMAIN to your Samba4 domain
 * Start the server with:

```
./samba4-manager
```

You may then connect through: [http://localhost:8080](http://localhost:8080)

# Contributing
Contributions are always appreciated!

The project is licensed under the GNU GPL version 2 (and any later version).
Contributors must sign-off on their commits, indicating that they agree with
the Developer Certificate of Ownership (developercertificate.org).
