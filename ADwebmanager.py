import logging
import argparse
from datetime import date
import os
from settings import Settings
app_prefix = "/opt/samba4-manager-master/"

# Check if running from bzr
for path in ('libs', 'plugins', 'static', 'templates'):
    if not os.path.exists(path):
        break
else:
    app_prefix = "."

parser = argparse.ArgumentParser(description="Samba4 Gestor Web")
args = parser.parse_args()

if not os.path.exists(app_prefix):
    raise Exception("Missing app dir: %s" % app_prefix)

# Import the rest of the stuff we need
from flask import Flask, g
import glob
import importlib

# Look at the right place
import sys
sys.path.append(app_prefix)

# Import our modules
from libs.common import ReverseProxied
from libs.common import iri_for as url_for
from settings import Settings

# Prepare the web server
app = Flask(__name__,
            static_folder="%s/static" % app_prefix,
            template_folder="%s/templates" % app_prefix)

if Settings.USE_LOGGING:
    import logging
    import sys

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', 
                                '%Y-%m-%d %H:%M:%S')

    stdout_handler = logging.StreamHandler(sys.stderr)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(f'./logs/{date.today()}-v3.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)
app.config.from_object(Settings)
app.jinja_env.globals['url_for'] = url_for

if 'URL_PREFIX' in app.config:
    app.wsgi_app = ReverseProxied(app.wsgi_app, app.config['URL_PREFIX'])

# Check for mandatory configuration
for key in ("LDAP_DOMAIN", "SECRET_KEY", "SEARCH_DN"):
    if key not in app.config:
        raise KeyError("Missing mandatory %s option in configuration." % key)

# LDAP configuration
if "LDAP_DN" not in app.config:
    app.config['LDAP_DN'] = "DC=%s" % ",DC=".join(
        app.config['LDAP_DOMAIN'].split("."))

if "LDAP_SERVER" not in app.config:
    import dns.resolver
    import dns.rdatatype
    import operator

    record = "_ldap._tcp.%s." % app.config['LDAP_DOMAIN']
    answers = []

    # Query the DNS
    try:
        for answer in dns.resolver.query(record, dns.rdatatype.SRV):
            address = (answer.target.to_text()[:-1], answer.port)
            answers.append((address, answer.priority, answer.weight))
    except:
        # Ignore exceptions, an empty list will trigger an exception anyway
        pass

    # Order by priority and weight
    servers = [entry[0][0] for entry in sorted(answers,
                                               key=operator.itemgetter(1, 2))]
    if not servers:
        raise Exception("No LDAP server in domain '%s'." %
                        app.config['LDAP_DOMAIN'])

    if len(servers) == 1:
        app.config['LDAP_SERVER'] = servers[0]
    else:
        app.config['LDAP_SERVER'] = servers

if "SICCIP_AWARE" not in app.config:
    app.config['SICCIP_AWARE'] = False

# Load the plugins
for plugin_file in glob.glob("%s/plugins/*.py" % app_prefix):
    plugin_name = plugin_file.split('/')[-1].replace('.py', '')
    if plugin_name == "__init__":
        continue

    plugin = importlib.import_module("plugins.%s" % plugin_name)
    plugin.init(app)


@app.before_request
def pre_request():
    """
        Setup any of the global variables before the request is processed.
    """
    g.menu = []
    g.menu.append((url_for("core_index"), "Mi Account"))
    g.menu.append((url_for("tree_base"), u"Directory"))
    g.menu.append((url_for("core_logout"), "Log out"))

    # LDAP connection settings
    g.ldap = {'domain': app.config['LDAP_DOMAIN'], 'dn': app.config['LDAP_DN'], 'server': app.config['LDAP_SERVER'],
              'search_dn': app.config['SEARCH_DN']}

    # The various caches
    g.ldap_cache = {}
    g.app_version = "v22.09.1"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
