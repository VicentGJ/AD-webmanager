from libs.common import iri_for as url_for
from flask import g, render_template, redirect, request
from wtforms import StringField, SelectField

from libs.ldap_func import ldap_auth, ldap_get_entries, ldap_in_group



def init(app):
    @app.route('/search', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")

    def search():
        admin = ldap_in_group("SM Admin")
        entry_fields = [('name', "Nombre"),
                        ('__description', u"Login/Descripción"),
                        ('__type', "Tipo"),
                        ('active', "Estado")]