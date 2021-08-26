# Introduction
This project is a web interface for Active Directory made using Flask and
python-ldap, focusing in easy of use and simplicity.

It's using the connecting user's own credentials to connect to the
directory and allow a variety of operations.

The goal is to be able to do most common directory operations directly
through this web interface rather than have to rely on command tools or
Windows interfaces.

Its compatible with both Windows Active Directory and Samba4 domain controllers.

The current version is a total overhoul of the original codebase, design to 
comply with more modern standars in web development. This repo currently host
a light backend API, and its not the final product.

# History
This project is a fork of samba4-manager, created by Stéphane Graber
and the Edubuntu community.
This project was pick up for internal use at Havana's Technology University (CUJAE)
in 2017, and since it has received numerous updates, additions, and changes.
We decided to release our version as a fork since the original project is
no longer in active development.
We will keep updating the project for our organization and the community, 
and we will love to receive all kinds of feedback and contributions.

# Running
This repo uses pipenv for dependencies and virtual environment magnament.

 * Run ```pipenv install``` in the project root folder
 * Run ```pipenv shell``` to activate the virtual environment
 * Access settings.py to configure
 * Put a random string in SECRET\_KEY
 * Set LDAP\_DOMAIN to your Directory domain
 * Set LDAP\_SERVER to your Domain Controller IP
 * Start the server with:

```
./ADwebmanager.py
```

You may then connect through: [http://localhost:8080](http://localhost:8080)

# Contributing
Contributions are always appreciated!

The project is licensed under the GNU GPL version 3.
Contributors must sign-off on their commits, indicating that they agree with
the Developer Certificate of Ownership (developercertificate.org).
