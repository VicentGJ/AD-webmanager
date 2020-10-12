# -*- coding: utf-8 -*-

# Copyright (C) 2012-2015 Stéphane Graber
# Author: Stéphane Graber <stgraber@ubuntu.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can find the license on Debian systems in the file
# /usr/share/common-licenses/GPL-2

from libs.common import iri_for as url_for
from flask import g, render_template, request, redirect
from libs.ldap_func import ldap_auth, ldap_get_entries, ldap_in_group
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField


TREE_BLACKLIST = ["CN=ForeignSecurityPrincipals",
                  "OU=sudoers"]

class FilterTreeView(FlaskForm):
    filter_str = StringField()
    filter_select = SelectField(choices=['sAMAccountName', 'displayName', 'cUJAEPersonDNI'])


def init(app):
    @app.route('/tree', methods=['GET', 'POST'] )
    @app.route('/tree/<base>', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    
    def tree_base(base=None):

        if not base:
            base = g.ldap['dn']
        elif not base.lower().endswith(g.ldap['dn'].lower()):
            base += ",%s" % g.ldap['dn']

        admin = ldap_in_group("SM Admin")
        entry_fields = [('name', "Nombre"),
                        ('__description', u"Login/Descripción"),
                        ('__type', "Tipo"),
                        ('active', "Estado")]

        form = FilterTreeView(request.form)

        if form.validate_on_submit():
            filter_str = form.filter_str.data
            filter_select = form.filter_select.data
            scope = "subtree"
            entries = get_entries(filter_str, filter_select, base, scope)
        else:
            filter_str = None
            scope = "onelevel"
            entries = get_entries("top", "objectClass", base, scope)
                    
        parent = None
        base_split = base.split(',')
        if not base_split[0].lower().startswith("dc"):
            parent = ",".join(base_split[1:])

        return render_template("pages/tree_base_es.html", form=form, parent=parent,
                               admin=admin, base=base, entries=entries,
                               entry_fields=entry_fields)

    def get_entries(filter_str, filter_select, base, scope):
        """
        Get all entries that will be displayed in the tree
        """
        entries = []
        
        users = ldap_get_entries("objectClass=top", base, scope, ignore_erros=True)
        users = filter(lambda entry: 'displayName' in entry, users)
        users = filter(lambda entry: 'sAMAccountName' in entry, users)
        users = filter(lambda entry: filter_str in entry[filter_select], users)
        users = sorted(users, key=lambda entry: entry['displayName'])
        if filter_str == "top":
            other_entries = ldap_get_entries("objectClass=top", base, scope, ignore_erros=True)
            other_entries = filter(lambda entry: 'displayName' not in entry, other_entries)
            other_entries = sorted(other_entries, key=lambda entry: entry['name'])
        else:
            other_entries = []
        for entry in users:
            if 'description' not in entry:
                if 'sAMAccountName' in entry:
                   entry['__description'] = entry['sAMAccountName']
            else:
                entry['__description'] = entry['description']

            entry['__target'] = url_for('tree_base', base=entry['distinguishedName'])

            entry['name'] = entry['displayName']
            entry['__type'] = "Usuario"
            entry['__target'] = url_for('user_overview', username=entry['sAMAccountName'])
            
            if 'user' in entry['objectClass']:
                if entry['userAccountControl'] == 512:
                    entry['active'] = "Activo"
                else:
                    entry['active'] = "Desactivado"
            else:
                entry['active'] = "No disponible"

            if 'showInAdvancedViewOnly' in entry \
               and entry['showInAdvancedViewOnly']:
                continue

            for blacklist in TREE_BLACKLIST:
                if entry['distinguishedName'].startswith(blacklist):
                    break

            entries.append(entry)
        
        for entry in other_entries:
            if entry not in users:
                if 'description' not in entry:
                    if 'sAMAccountName' in entry:
                        entry['__description'] = entry['sAMAccountName']
                else:
                    entry['__description'] = entry['description']
                
                entry['__target'] = url_for('tree_base', base=entry['distinguishedName'])

                if 'group' in entry['objectClass']:
                    entry['__type'] = "Grupo"
                    entry['__target'] = url_for('group_overview',
                                                groupname=entry['sAMAccountName'])
                elif 'organizationalUnit' in entry['objectClass']:
                    entry['__type'] = "Unidad Organizativa"
                elif 'container' in entry['objectClass']:
                    entry['__type'] = "Contenedor"
                elif 'builtinDomain' in entry['objectClass']:
                    entry['__type'] = "Built-in"
                else:
                    entry['__type'] = "Desconocido"

                
                entries.append(entry)
        return entries