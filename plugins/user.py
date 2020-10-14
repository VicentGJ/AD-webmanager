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
from flask import abort, flash, g, render_template, redirect, request
from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectMultipleField, TextAreaField, \
    TextField, StringField, FieldList, SelectField, DecimalField, IntegerField, BooleanField
from wtforms.validators import Required,  EqualTo, Optional


from libs.ldap_func import ldap_auth, ldap_change_password, \
    ldap_create_entry, ldap_delete_entry, ldap_get_user, \
    ldap_get_membership, ldap_get_group, ldap_in_group, ldap_get_entry_simple, \
    ldap_update_attribute, ldap_user_exists, ldap_get_entries, LDAP_AD_USERACCOUNTCONTROL_VALUES

from libs.common import get_parsed_pager_attribute

import ldap

class UserSSHEdit(FlaskForm):
    ssh_keys = TextAreaField('Llaves SSH')


class UserAddGroup(FlaskForm):
    available_groups = SelectField('Grupos')


class UserProfileEdit(FlaskForm):
    first_name = StringField('Nombre', [Required()])
    last_name = StringField('Apellido', [Required()])
    display_name = StringField('Nombre Completo')
    user_name = StringField('Nombre de Usuario', [Required()])
    mail = StringField(u'Dirección de correo')
    aliases = FieldList(StringField(), label=u'Otras direcciones de correo - Aliases')
    cujae_category = SelectField(label='Categoría', choices=[('A', 'Categoría A'), ('B', 'Categoría B'), ('C', 'Categoría C')])
    uac_flags = SelectMultipleField('Estado', coerce=int)


class SICCIPEdit(FlaskForm):
    manual = BooleanField('Manual')
    category = SelectField(u'Categoría de la cuenta', [Required()],
                                choices=[('A', u'Acceso Total'),
                                         ('B', u'Acceso con restricciones'),
                                         ('C', u'Menor Acceso')])


class UserAdd(UserProfileEdit):
    base = None
    cujae_type = SelectField('Trabajador o Estudiante?', [Required()])
    cujae_dni = StringField('Carné de Identidad', [Required()])
    cujae_teacher = SelectField('Profesor?', [Required()], choices=["TRUE", "FALSE"])
    cujae_external = SelectField('Usuario Externo?', [Required()], choices=["TRUE", "FALSE"])
    password = PasswordField(u'Contraseña', [Required()])
    password_confirm = PasswordField(u'Repetir contraseña',
                                     [Required(),
                                      EqualTo('password',
                                              message=u'Las contraseñas deben coincidir')])


class PasswordChange(FlaskForm):
    password = PasswordField(u'Nueva Contraseña', [Required()])
    password_confirm = PasswordField(u'Repetir Nueva Contraseña',
                                     [Required(),
                                      EqualTo('password',
                                              message=u'Las contraseñas deben coincidir')])


class PasswordChangeUser(PasswordChange):
    oldpassword = PasswordField(u'Contraseña actual', [Required()])


def init(app):
    @app.route('/users/+add', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    def user_add():
        title = "Adicionar Usuario"

        if not UserAdd.base:
            UserAdd.base = request.args.get('base')
        #if not base:
        #    base = "CN=Users,%s" % g.ldap['dn']
        base = UserAdd.base
        print(base, "fist base")

        form = UserAdd(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('displayName', form.display_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         ('cUJAEPersonType', form.cujae_type),
                         ('cUJAEPersonDNI', form.cujae_dni),
                         ('cUJAEWorkerTeacher', form.cujae_teacher),
                         ('cUJAEPersonExternal', form.cujae_external),
                         ('pager', form.cujae_category),
                         (None, form.password),
                         (None, form.password_confirm),
                         ('userAccountControl', form.uac_flags)]

        form.visible_fields = [field[1] for field in field_mapping]
        form.cujae_type.choices = ["Worker", "Student"]
        form.uac_flags.choices = [(key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]

        print(base, "secund base")

        if form.validate_on_submit():
            try:
                print(base, "third base")
                # Default attributes
                upn = "%s@%s" % (form.user_name.data, g.ldap['domain'])
                attributes = {'objectClass': [b'top', b'person', b'organizationalPerson', b'user', b'inetOrgPerson'],
                              'UserPrincipalName': [upn.encode('utf-8')],
                              'accountExpires': [b"0"],
                              'lockoutTime': [b"0"]}

                for attribute, field in field_mapping:
                    if attribute == 'userAccountControl':
                        current_uac = 512
                        for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                            if flag[1] and key in field.data:
                                current_uac += key
                        attributes[attribute] = [str(current_uac).encode('utf-8')]
                    elif attribute and field.data:
                        attributes[attribute] = [field.data.encode('utf-8')]
                
                # As a CUJAE specific change I use the dni to create the user
                ldap_create_entry("cn=%s,%s" % (form.cujae_dni.data, base),
                                  attributes)
                print("cn=%s,%s" % (form.user_name.data, base))
                ldap_change_password(None, form.password.data,
                                     form.user_name.data)
                flash(u"Usuario creado con éxito.", "success")
                return redirect(url_for('user_overview',
                                        username=form.user_name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            flash("Some fields failed validation.", "error")

        if len(form.aliases.entries) == 0:
            for number in range(1,3):
                form.aliases.append_entry()

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Adicionar Usuario",
                               parent=url_for('user_add'))


    @app.route('/user/<username>', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_overview(username):
        title = "Detalles del Usuario - %s" % username

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        admin = ldap_in_group("SM Admin")
        cujae_external = user['cUJAEPersonExternal']
        logged_user = g.ldap['username']
        
        if logged_user == user['sAMAccountName'] or admin:

            identity_fields = [('givenName', "Nombre"),
                               ('sn', "Apellidos"),
                               ('displayName', "Nombre Completo"),
                               ('name', "Carnet de Identidad"),
                               ('sAMAccountName', "Nombre de Usuario"),
                               ('mail', u"Dirección de Correo"),
                               ('pager', "Categoría")]
            group_fields = [('sAMAccountName', "Nombre"),
                            ('description', u"Descripción")]

            
            user = ldap_get_user(username=username)
            group_details = [ldap_get_group(group, 'distinguishedName')
                            for group in ldap_get_membership(username)]

            groups = sorted(group_details, key=lambda entry:
                            entry['sAMAccountName'])

            available_groups = ldap_get_entries(ldap_filter="(objectclass=group)", scope="subtree")
            group_choices = [("_","Seleccione un Grupo")]
            for group_entry in available_groups:
                if not ldap_in_group(group_entry['sAMAccountName'],username):
                    group_choices += [(group_entry['distinguishedName'],group_entry['sAMAccountName'])]

            form = UserAddGroup(request.form)
            form.available_groups.choices = group_choices

            if not form.is_submitted():
                form.available_groups.data = "_"

            if form.validate_on_submit():
                try:
                    group_to_add = form.available_groups.data
                    if group_to_add == "_":
                        flash(u"Debe escoger un grupo de la lista desplegable.", "error")
                    else:
                        group = ldap_get_entry_simple({'objectClass': 'group', 'distinguishedName': group_to_add})
                        if 'member' in group:
                            entries = set(group['member'])
                        else:
                            entries = set()
                        entries.add(user['distinguishedName'])
                        ldap_update_attribute(group_to_add, "member", list(entries))
                        flash(u"Usuario añadido con éxito al grupo.", "success")
                    return redirect(url_for('user_overview',username=username))
                except ldap.LDAPError as e:
                    e = dict(e.args[0])
                    flash(e['info'], "error")
            elif form.errors:
                    flash(u"Falló la validación de los datos.", "error")

            parent = ",".join(user['distinguishedName'].split(',')[1:])
        
        else:
            abort(401)

        return render_template("pages/user_overview_es.html", g=g, title=title, form=form,
                               user=user, identity_fields=identity_fields,
                               group_fields=group_fields, admin=admin, external=cujae_external, groups=groups,
                               parent=parent, uac_values=LDAP_AD_USERACCOUNTCONTROL_VALUES)


    @app.route('/user/<username>/+changepw', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_changepw(username):
        title = u"Cambiar contraseña"

        if not ldap_user_exists(username=username):
            abort(404)

        admin = ldap_in_group("SM Admin")
        if username != g.ldap['username'] and admin:
            form = PasswordChange(request.form)
            form.visible_fields = []
        else:
            form = PasswordChangeUser(request.form)
            form.visible_fields = [form.oldpassword]

        form.visible_fields += [form.password, form.password_confirm]

        if form.validate_on_submit():
            try:
                if username != g.ldap['username'] and admin:
                    ldap_change_password(None,
                                         form.password.data,
                                         username=username)
                else:
                    ldap_change_password(form.oldpassword.data,
                                         form.password.data,
                                         username=username)
                flash(u"La contraseña se cambió con éxito.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
                flash(u"Falló la validación de los datos.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action=u"Cambiar contraseña",
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+delete', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    def user_delete(username):
        title = "Borrar Usuario"

        if not ldap_user_exists(username=username):
            abort(404)

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                user = ldap_get_user(username=username)
                ldap_delete_entry(user['distinguishedName'])
                flash(u"Usuario borrado con éxito.", "success")
                return redirect(url_for('core_index'))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
                flash(u"Falló la validación de los datos.", "error")

        return render_template("pages/user_delete_es.html", title=title,
                               action="Borrar Usuario", form=form,
                               username=username,
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-profile', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    def user_edit_profile(username):
        title = "Editar usuario"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        form = UserProfileEdit(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('displayName', form.display_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         ('otherMailbox', form.aliases),
                         ('pager', form.cujae_category),
                         ('userAccountControl', form.uac_flags)]

        form.uac_flags.choices = [(key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]

        form.visible_fields = [field[1] for field in field_mapping]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != user.get(attribute):
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(user['distinguishedName'],"sAMAccountName", value)
                            ldap_update_attribute(user['distinguishedName'],"userPrincipalName", "%s@%s" % (value, g.ldap['domain']))
                            # Finish by renaming the whole record
                            ldap_update_attribute(user['distinguishedName'],"cn", value)
                            user = ldap_get_user(value)
                        elif attribute == 'userAccountControl':
                            current_uac = 512
                            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                                if flag[1] and key in field.data:
                                    current_uac += key
                            ldap_update_attribute(user['distinguishedName'], attribute, str(current_uac)) 
                        else:
                            ldap_update_attribute(user['distinguishedName'], attribute, value)

                flash(u"Perfil actualizado con éxito.", "success")
                return redirect(url_for('user_overview', username=form.user_name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            flash(u"Falló la validación de los datos.", "error")

        if not form.is_submitted():
            form.first_name.data = user.get('givenName')
            form.last_name.data = user.get('sn')
            form.display_name.data = user.get('displayName')
            form.user_name.data = user.get('sAMAccountName')
            form.mail.data = user.get('mail')
            aliases = user.get('otherMailbox')
            if isinstance(aliases,list):
                for alias in aliases:
                    form.aliases.append_entry(alias)
            form.aliases.append_entry()
            form.uac_flags.data = [key for key, flag in
                                   LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                   if (flag[1] and
                                       user['userAccountControl'] & key)]

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview',
                                              username=username))


    @app.route('/user/<username>/+edit-ssh', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    def user_edit_ssh(username):
        title = "Editar llaves SSH"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)

        form = UserSSHEdit(request.form)
        form.visible_fields = [form.ssh_keys]

        if form.validate_on_submit():
            new_entries = [entry.strip() for entry in
                           form.ssh_keys.data.split("\n")]
            try:
                ldap_update_attribute(user['distinguishedName'],
                                      'sshPublicKey', new_entries,
                                      'ldapPublicKey')
                flash("SSH keys successfuly updated.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            flash(u"Falló la validación de los datos.", "error")

        if not form.is_submitted():
            if 'sshPublicKey' in user:
                form.ssh_keys.data = "\n".join(user['sshPublicKey'])

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview',
                                              username=username))


    @app.route('/user/<username>/+edit-groups', methods=['GET', 'POST'])
    @ldap_auth("SM Admin")
    def user_edit_groups(username):
        title = "Editar pertenencia a Grupos"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)

        form = UserGroupEdit(request.form)
        form.visible_fields = [form.ssh_keys]

        if form.validate_on_submit():
            try:
                ldap_update_attribute(user['distinguishedName'],
                                      'sshPublicKey', new_entries,
                                      'ldapPublicKey')
                flash(u"Pertenencia a grupos modificada con éxito.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            flash(u"Falló la validación de los datos.", "error")

        if not form.is_submitted():
            if 'sshPublicKey' in user:
                form.ssh_keys.data = "\n".join(user['sshPublicKey'])

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview',
                                              username=username))
