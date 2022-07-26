from flask import g, redirect, session
from libs.common import iri_for as url_for
from libs.ldap_func import ldap_auth, ldap_get_entry_simple


def init(app):
    @app.route('/')
    @app.route('/user')
    @ldap_auth("Domain Users")
    def core_index():
        return redirect(url_for('user_overview', username=g.ldap['username']))

    @app.route('/+logout')
    @ldap_auth("Domain Users")
    def core_logout():
        session['logout'] = 1
        return redirect(url_for('core_index'))
