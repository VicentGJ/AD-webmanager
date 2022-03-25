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

from email.mime import base
from operator import indexOf
import struct

import ldap
from flask import abort, flash, g, redirect, render_template, request
from flask_wtf import FlaskForm
from libs.common import iri_for as url_for, namefrom_dn
from libs.ldap_func import (LDAP_AD_GROUPTYPE_VALUES, ldap_add_users_to_group,
                            ldap_auth, ldap_create_entry, ldap_delete_entry,
                            ldap_get_entry_simple, ldap_get_group,
                            ldap_get_members, ldap_get_membership,
                            ldap_group_exists, ldap_in_group,
                            ldap_update_attribute)
from settings import Settings
from wtforms import RadioField, StringField, TextAreaField
from wtforms.validators import DataRequired


class GroupDelMember(FlaskForm):
    pass


class GroupAddMembers(FlaskForm):
    new_members = TextAreaField('New members')


class GroupEdit(FlaskForm):
    name = StringField('Name', [DataRequired()])
    description = StringField(u'Description')
    mail = StringField(u'Mail')
    group_type = RadioField('Type',
                            choices=[(2147483648, 'Security Group'),
                                     (0, u'Distribution list')],
                            coerce=int)
    group_flags = RadioField(u'Ambit', coerce=int)


def init(app):
    @app.route('/groups/+add', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_add():
        title = "Add group"

        form = GroupEdit(request.form)
        field_mapping = [('sAMAccountName', form.name),
                         ('description', form.description),
                         ('mail', form.mail),
                         (None, form.group_type),
                         ('groupType', form.group_flags)]

        form.visible_fields = [field[1] for field in field_mapping]

        form.group_flags.choices = [(key, value[0]) for key, value in
                                    LDAP_AD_GROUPTYPE_VALUES.items()
                                    if value[1]]

        if form.validate_on_submit():
            try:
                base = request.args.get("b'base")
                base = base.rstrip("'")
                # Default attributes
                attributes = {'objectClass': b"group"}

                for attribute, field in field_mapping:
                    if attribute == "groupType":
                        group_type = int(form.group_type.data) + int(form.group_flags.data)
                        attributes[attribute] = str(struct.unpack("i",
                                                                  struct.pack("I", int(group_type)))[0]).encode('utf-8')
                    elif attribute and field.data:
                        attributes[attribute] = field.data.encode('utf-8')
                print(attributes)
                print("cn=%s,%s" % (form.name.data, base))
                ldap_create_entry("cn=%s,%s" % (form.name.data, base), attributes)

                flash(u"Group created successfully.", "success")
                return redirect(url_for('group_overview',
                                        groupname=form.name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            flash(u"Data validation failed.", "error")

        if not form.is_submitted():
            form.group_type.data = 2147483648
            form.group_flags.data = 2

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add group",
                               parent=url_for('tree_base'))

    @app.route('/group/<groupname>')
    @ldap_auth("Domain Users")
    def group_overview(groupname):
        title = "Group details - %s" % groupname

        if not ldap_group_exists(groupname=groupname):
            abort(404)

        identity_fields = [('sAMAccountName', "Name"),
                           ('description', u"Description")]

        group_fields = [('sAMAccountName', "Name"),
                        ('description', u"Description")]

        group = ldap_get_group(groupname=groupname)

        admin = ldap_in_group(Settings.ADMIN_GROUP) and not group['groupType'] & 1

        group_details = [ldap_get_group(entry, 'distinguishedName')
                         for entry in ldap_get_membership(groupname)]

        group_details = list(filter(None, group_details))
        groups = sorted(group_details, key=lambda entry: entry['sAMAccountName'])

        member_list = []
        for entry in ldap_get_members(groupname):
            member = ldap_get_entry_simple({'distinguishedName': entry})
            if 'sAMAccountName' not in member:
                continue
            member_list.append(member)

        members = sorted(member_list, key=lambda entry:
                         entry['sAMAccountName'])

        parent = ",".join(group['distinguishedName'].split(',')[1:])
        parent_name = namefrom_dn(parent)
        return render_template("pages/group_overview_es.html", g=g, title=title,
                               group=group, identity_fields=identity_fields,
                               group_fields=group_fields, admin=admin,
                               groups=groups, members=members, parent=parent,
                               parent_name=parent_name,
                               grouptype_values=LDAP_AD_GROUPTYPE_VALUES)

    @app.route('/group/<groupname>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_delete(groupname):
        title = "Delete group"

        if not ldap_group_exists(groupname):
            abort(404)

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                group = ldap_get_group(groupname=groupname)
                ldap_delete_entry(group['distinguishedName'])
                flash(u"Group removed successfully.", "success")
                return redirect(url_for('core_index'))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
                flash(u"Data validation failed.", "error")

        return render_template("pages/group_delete_es.html", title=title,
                               action="Delete group", form=form,
                               groupname=groupname,
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+edit', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_edit(groupname):
        title = "Edit group"

        if not ldap_group_exists(groupname):
            abort(404)

        group = ldap_get_group(groupname)

        # We can't edit system groups
        if group['groupType'] & 1:
            abort(401)

        form = GroupEdit(request.form)
        field_mapping = [('sAMAccountName', form.name),
                         ('description', form.description),
                         ('mail', form.mail),
                         (None, form.group_type),
                         ('groupType', form.group_flags)]

        form.visible_fields = [field[1] for field in field_mapping]

        form.group_flags.choices = [(key, value[0]) for key, value in
                                    LDAP_AD_GROUPTYPE_VALUES.items()
                                    if value[1]]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != group.get(attribute):
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(group['distinguishedName'],
                                                  "sAMAccountName", value)
                            # Finish by renaming the whole record
                            dn: str = group['distinguishedName'].split(",", 1)[1]
                            dn = "CN={0},{1}".format(value, dn)
                            ldap_update_attribute(group['distinguishedName'],
                                                  "distinguishedName", "CN={0}".format(value))
                            group['distinguishedName'] = dn
                        elif attribute == "groupType":
                            group_type = int(form.group_type.data) + \
                                int(form.group_flags.data)
                            ldap_update_attribute(
                                group['distinguishedName'], attribute,
                                str(
                                    struct.unpack(
                                        "i", struct.pack(
                                            "I", int(group_type)))[0]))
                        elif attribute:
                            ldap_update_attribute(group['distinguishedName'],
                                                  attribute, value)

                flash(u"Successfully modified group.", "success")
                return redirect(url_for('group_overview',
                                        groupname=form.name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")

        elif form.errors:
            flash(u"Data verification failed.", "error")

        if not form.is_submitted():
            form.name.data = group.get('sAMAccountName')
            form.description.data = group.get('description')
            form.mail.data = group.get('mail')
            form.group_type.data = group['groupType'] & 2147483648
            form.group_flags.data = 0
            for key, flag in LDAP_AD_GROUPTYPE_VALUES.items():
                if flag[1] and group['groupType'] & key:
                    form.group_flags.data += key

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Save changes",
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_addmembers(groupname):
        title = "Add members"

        if not ldap_group_exists(groupname):
            abort(404)

        form = GroupAddMembers(request.form)
        form.visible_fields = [form.new_members]

        if form.validate_on_submit():
            group = ldap_get_group(groupname)
            if 'member' in group:
                entries = set(group['member'])
            else:
                entries = set()

            for line in form.new_members.data.split("\n"):
                entry = ldap_get_entry_simple({'sAMAccountName': line.strip()})
                if not entry:
                    error = u"Invalid username: %s" % line
                    flash(error, "error")
                    break

                entries.add(entry['distinguishedName'])
            else:
                try:
                    ldap_add_users_to_group(group['distinguishedName'],
                                          "member", list(entries))
                    flash("Added users.", "success")
                    return redirect(url_for('group_overview',
                                            groupname=groupname))
                except ldap.LDAPError as e:
                    e = dict(e.args[0])
                    flash(e['info'], "error")
        elif form.errors:
            flash(u"Data validation failed.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Adicionar miembros",
                               parent=url_for('group_overview',
                                              groupname=groupname))

    @app.route('/group/<groupname>/+del-member/<member>',
               methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_delmember(groupname, member):
        title = "Remove from group"

        group = ldap_get_group(groupname)
        if not group or 'member' not in group:
            abort(404)

        member = ldap_get_entry_simple({'sAMAccountName': member})
        if not member:
            abort(404)

        if not member['distinguishedName'] in group['member']:
            abort(404)

        form = GroupDelMember(request.form)

        if form.validate_on_submit():
            try:
                members = group['member']
                members.remove(member['distinguishedName'])
                ldap_update_attribute(group['distinguishedName'],"member", members)
                flash("Member of group X %s eliminated" % group['sAMAccountName'], "success")
                return redirect(url_for('user_overview', username=member['sAMAccountName']))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
                flash(u"Data validation failed.", "error")

        return render_template("pages/group_delmember_es.html", title=title,
                               action="Remove member from group", form=form,
                               member=member['sAMAccountName'],
                               group=group['sAMAccountName'],
                               parent=url_for('user_overview', username=member['sAMAccountName']))
