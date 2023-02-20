# Introduction

This project is a web interface for Active Directory made using Flask and
python-ldap, focusing on ease of use and simplicity.

It's using the connecting user's credentials to connect to the
directory and allow a variety of operations.

The goal is to be able to do most common directory operations directly
through this web interface rather than have to rely on command tools or
Windows interfaces.

It's compatible with both Windows Active Directory and Samba4 domain controllers.

# History

This project started as a fork of samba4-manager, created by Stéphane Graber
and the Edubuntu community.
Was used internally at Havana's Technology University in 2017, and since it has
received numerous updates, additions, and changes.
We decided to release our version publicly since the original project was not being
regularly updated. It has grown since to a much more capable application.
The project is now maintained by [GSI General Software Inc.](https://www.generalsoftwareinc.com/)
We will keep updating the project for our organization and the community,
and we are open to all kinds of feedback and contributions.

# Install and run

Note: all code has only been tested and it's supported to run on Linux systems, contributions
regarding compatibility with other platforms is welcomed.

## Local config

* Create the .env file in the root directory
  * Put a random string in SECRET\_KEY**
  * Set LDAP\_DOMAIN to your Directory domain
  * Set SEARCH\_DN to your Directory LDAP search base
  * Set LDAP\_SERVER to your Domain Controller IP
  * Use DEBUG = True if you want the test server to immediately reload after changes
  * Set USE_LOGGING = True if you want to log to files and console, false logs to console only
  * Set ADMIN\_GROUP to the security group with read/write permission (default should be Domain Admins)
* Create settings.py to configure**
* ADD to TREE\_BLACKLIST the containers you want to hide in the root directory
* Add attribute pairs to SEARCH\_ATTRS and TREE\_ATTRIBUTES to customize the tree view

### Setup Environment

Copy the .env.example file to .env and udpate the settings to match your environment.

```sh
cp .env.example .env
```

You can install the dependencies using pip and the supplied requirements.txt. Especial
consideration to the python-ldap dependency, which depends on native C libraries and as such needs
native compilers and tooling to be installed ([check python-ldap docs here](https://www.python-ldap.org/en/python-ldap-3.4.0/installing.html#build-prerequisites)).

## Installing dependencies in Ubuntu 20.04 or Debian 11

 **Note: We assume you are running those commands with in the procject root directory**

```sh
apt update
apt install python3-venv python3-pip
apt install build-essential python3-dev libldap2-dev libsasl2-dev ldap-utils tox lcov valgrind
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
```

## For running in local

```sh
python3 ADwebmanager.py
```

## For running with Docker

```sh
docker build -t <image name> .
#after image succsessfully built
docker run -d -p 8080:8080 <image name>
```

You may then connect through [http://localhost:8080](http://localhost:8080)

# Contributing

Contributions are always appreciated!

The project is under the MIT license.
