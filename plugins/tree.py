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

from urllib import parse

import ldap
from flask import abort, flash, g, redirect, render_template, request
from flask_wtf import FlaskForm
from libs.common import get_objclass
from libs.common import iri_for as url_for
from libs.common import namefrom_dn
from libs.ldap_func import (ldap_auth, ldap_delete_entry, ldap_get_entries,
                            ldap_get_group, ldap_get_ou, ldap_get_user,
                            ldap_in_group, ldap_obj_has_children)
from settings import Settings
from wtforms import SelectField, StringField, SubmitField


class FilterTreeView(FlaskForm):
    filter_str = StringField()
    filter_select = SelectField(choices=Settings.SEARCH_ATTRS)
    search = SubmitField('Search')


class BatchSelect(FlaskForm):
    delete = SubmitField('Delete Selection')

def init(app):
    @app.route('/tree', methods=['GET', 'POST'])
    @app.route('/tree/<base>', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def tree_base(base=None):
        if not base:
            base = g.ldap['dn']
        elif not base.lower().endswith(g.ldap['dn'].lower()):
            base += ",%s" % g.ldap['dn']

        admin = ldap_in_group(Settings.ADMIN_GROUP)

        if not admin:
            abort(401)
        else:
            entry_fields = [('name', "Name"),
                            ('__description', u"Login/Description")]
            
            if Settings.TREE_ATTRIBUTES:
                for item in Settings.TREE_ATTRIBUTES:
                    entry_fields.append((item[0], item[1])) 

            form = FilterTreeView(request.form)
            batch_select = BatchSelect()

            if form.search.data and form.validate():
                print('here 1')
                filter_str = form.filter_str.data
                filter_select = form.filter_select.data
                scope = "subtree"
                entries = get_entries(filter_str, filter_select, base, scope)     
            else:
                filter_str = None
                scope = "onelevel"
                entries = get_entries("top", "objectClass", base, scope)
            
           #TODO: batch delete confirmation page
            if batch_select.delete.data:
                #delete all selections
                checkedDataToDelete = request.form.getlist("checkedItems") #returns an array of Strings, tho the strings have dict format
                toDelete = []
                for x in checkedDataToDelete: #transform all strings to dicts and append them to a new list
                    dicts = {}
                    key1 = x.split("name:'")[1].split("'")[0]
                    key2 = x.split("type:'")[1].split("'")[0]
                    key3 = x.split("target:'")[1].replace("'}", "") 
                    key4 = key3.split("/")[2] # getting the username from the target url
                    dicts['name'] = key1
                    dicts['type'] = key2
                    dicts['target'] = key3
                    if key2 != 'Organization Unit':
                        dicts['username'] = key4
                    else:
                        dicts['dn'] = parse.unquote(key4)

                    toDelete.append(dicts)
                #all selections are saved in toDelete list as dicts
                try:
                    for obj in toDelete:
                        for key in obj:
                            if key == 'type':
                                if obj[key] == 'User':
                                    user = ldap_get_user(username=obj['username'])
                                    ldap_delete_entry(user['distinguishedName'])
                                elif obj[key] == 'Group':
                                    group = ldap_get_group(groupname=obj['name'])
                                    ldap_delete_entry(group['distinguishedName'])
                                elif obj[key] == 'Organization Unit':
                                    canDelete = not ldap_obj_has_children(base=obj['dn'])
                                    ou = ldap_get_ou(ou_name=obj['dn'])
                                    if canDelete:
                                        ldap_delete_entry(ou['distinguishedName'])
                                    else:
                                        flash(f"Can't delete OU: '{ou['ou']}' because is not empty", "error")
                except ldap.LDAPError as e:
                    flash(e,"error")
                return redirect(url_for('tree_base', base=base))

        parent = None
        base_split = base.split(',')
        if not base_split[0].lower().startswith("dc"):
            parent = ",".join(base_split[1:])

        name = namefrom_dn(base)
        return render_template("pages/tree_base_es.html", form=form, parent=parent, batch_select=batch_select,
                                admin=admin, base=base.upper(), entries=entries,
                                entry_fields=entry_fields, root=g.ldap['search_dn'].upper(), name=name,
                                objclass=get_objclass(base))

    def get_entries(filter_str, filter_select, base, scope):
        """
        Get all entries that will be displayed in the tree
        """
        entries = []

        users = ldap_get_entries("objectClass=top", base, scope, ignore_erros=True)
        users = filter(lambda entry: 'displayName' in entry, users)
        users = filter(lambda entry: 'sAMAccountName' in entry, users)
        users = filter(lambda entry: filter_select in entry, users)
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
            entry['__type'] = "User"
            entry['__target'] = url_for('user_overview', username=entry['sAMAccountName'])

            if 'user' in entry['objectClass']:
                if entry['userAccountControl'] == 2:
                    entry['active'] = "Deactivated"
                else:
                    entry['active'] = "Active"
            else:
                entry['active'] = "No available"

            if 'showInAdvancedViewOnly' in entry and entry['showInAdvancedViewOnly']:
                continue
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
                    entry['__type'] = "Group"
                    entry['__target'] = url_for('group_overview',
                                                groupname=entry['sAMAccountName'])
                elif 'organizationalUnit' in entry['objectClass']:
                    entry['__type'] = "Organization Unit"
                elif 'container' in entry['objectClass']:
                    entry['__type'] = "Container"
                elif 'builtinDomain' in entry['objectClass']:
                    entry['__type'] = "Built-in"
                else:
                    entry['__type'] = "Unknown"
                entries.append(entry)
                for blacklist in Settings.TREE_BLACKLIST:
                    if entry['distinguishedName'].startswith(blacklist):
                        entries.remove(entry)
        return entries
