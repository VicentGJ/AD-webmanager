# -*- coding: utf-8 -*-

# Copyright (C) 2012-2015 Stéphane Graber
# Author: Stéphane Graber <stgraber@ubuntu.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You can find the license on Debian systems in the file
# /usr/share/common-licenses/GPL-2

import ldap
from flask import abort, flash, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from libs.ldap_func import (ldap_auth, ldap_create_entry, ldap_delete_entry,
                            ldap_get_ou, ldap_update_attribute)
from settings import Settings
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Optional


class OU_form(FlaskForm):
    ou_name = StringField(label='OU name', validators=[DataRequired()])
    ou_description = TextAreaField(label='OU description', validators=[Optional()])


def init(app):
    @app.route('/ou/+add', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_add():
        title = "Add OU"
        form: FlaskForm = OU_form(request.form)
        
        field_mapping = [('description', form.ou_description)]
        
        form.visible_fields = [field[1] for field in field_mapping]
        form.visible_fields.insert(0, form.ou_name)

        if form.validate_on_submit():
            try:
                base = request.args.get("b'base")
                base = base.rstrip("'")
                attributes = {
                    'objectClass': b"organizationalUnit",
                    }
                for attribute, field in field_mapping:
                    attributes[attribute] = field.data.encode('utf-8')

                ldap_create_entry("ou=%s,%s" % (form.ou_name.data, base), attributes)
                flash(u"OU created successfully.", "success")
 
                return redirect(url_for('tree_base', base=base))

            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")

        elif form.errors:
          flash(u"Data validation failed.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add OU",
                               parent=url_for('tree_base'))
                   
    @app.route('/ou/<ou_name>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_delete(ou_name):
        title = "Delete OU"

        # if not ldap_group_exists(ou_name):
        #     abort(404)

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                ou = ldap_get_ou(ou_name=ou_name)
                ldap_delete_entry(ou['distinguishedName'])
                flash(u"OU removed successfully.", "success")
                return redirect(url_for('core_index'))

            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
                
        elif form.errors:
                flash(u"Data validation failed.", "error")

        return render_template("pages/ou_delete_es.html", title=title,
                               action="Delete OU", form=form,
                               ou_name=ou_name,
                               parent=url_for('tree_base'))

    @app.route('/ou/<ou_name>/+edit', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_edit(ou_name):
        title = "Edit OU"

        ou = ldap_get_ou(ou_name)

        form = OU_form(request.form)
        field_mapping = [('description', form.ou_description)]
        
        form.visible_fields = [field[1] for field in field_mapping]

        form.visible_fields.insert(0, form.ou_name)

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != group.get(attribute):
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(ou['distinguishedName'],
                                                  "sAMAccountName", value)
                            # Finish by renaming the whole record
                            ldap_update_attribute(group['distinguishedName'],
                                                  "cn", value)
                            group = ldap_get_group(value)
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

    # @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    # @ldap_auth(Settings.ADMIN_GROUP)
    # def group_addmembers(groupname):
    #     title = "Add members"

    #     if not ldap_group_exists(groupname):
    #         abort(404)

    #     form = GroupAddMembers(request.form)
    #     form.visible_fields = [form.new_members]

    #     if form.validate_on_submit():
    #         group = ldap_get_group(groupname)
    #         if 'member' in group:
    #             entries = set(group['member'])
    #         else:
    #             entries = set()

    #         for line in form.new_members.data.split("\n"):
    #             entry = ldap_get_entry_simple({'sAMAccountName': line.strip()})
    #             if not entry:
    #                 error = u"Invalid username: %s" % line
    #                 flash(error, "error")
    #                 break

    #             entries.add(entry['distinguishedName'])
    #         else:
    #             try:
    #                 ldap_add_users_to_group(group['distinguishedName'],
    #                                       "member", list(entries))
    #                 flash("Added users.", "success")
    #                 return redirect(url_for('group_overview',
    #                                         groupname=groupname))
    #             except ldap.LDAPError as e:
    #                 e = dict(e.args[0])
    #                 flash(e['info'], "error")
    #     elif form.errors:
    #         flash(u"Data validation failed.", "error")

    #     return render_template("forms/basicform.html", form=form, title=title,
    #                            action="Adicionar miembros",
    #                            parent=url_for('group_overview',
    #                                           groupname=groupname))

    # @app.route('/group/<groupname>/+del-member/<member>',
    #            methods=['GET', 'POST'])
    # @ldap_auth(Settings.ADMIN_GROUP)
    # def group_delmember(groupname, member):
    #     title = "Remove from group"

    #     group = ldap_get_group(groupname)
    #     if not group or 'member' not in group:
    #         abort(404)

    #     member = ldap_get_entry_simple({'sAMAccountName': member})
    #     if not member:
    #         abort(404)

    #     if not member['distinguishedName'] in group['member']:
    #         abort(404)

    #     form = GroupDelMember(request.form)

    #     if form.validate_on_submit():
    #         try:
    #             members = group['member']
    #             members.remove(member['distinguishedName'])
    #             ldap_update_attribute(group['distinguishedName'],"member", members)
    #             flash("Member of group X %s eliminated" % group['sAMAccountName'], "success")
    #             return redirect(url_for('user_overview', username=member['sAMAccountName']))
    #         except ldap.LDAPError as e:
    #             e = dict(e.args[0])
    #             flash(e['info'], "error")
    #     elif form.errors:
    #             flash(u"Data validation failed.", "error")

    #     return render_template("pages/group_delmember_es.html", title=title,
    #                            action="Remove member from group", form=form,
    #                            member=member['sAMAccountName'],
    #                            group=group['sAMAccountName'],
    #                            parent=url_for('user_overview', username=member['sAMAccountName']))