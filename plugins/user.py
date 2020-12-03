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
    StringField, SelectField, DecimalField, IntegerField, BooleanField
from wtforms.validators import DataRequired,  EqualTo, Optional


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
    first_name = StringField('Nombre', [DataRequired()])
    last_name = StringField('Apellido')
    display_name = StringField('Nombre Completo')
    user_name = StringField('Nombre de Usuario', [DataRequired()])
    mail = StringField(u'Dirección de correo')
    # TODO: Erase this for master
    category = SelectField(choices=[('Auto', 'Automático'),
                                    ('A', 'Categoria A'),
                                    ('B', 'Categoria B'),
                                    ('C', 'Categoria C'),
                                    ('D', 'Sin Internet')])
    uac_flags = SelectMultipleField('Estado', coerce=int)


class SICCIPEdit(FlaskForm):
    internet_type = SelectField(u'Tipo de acceso a Internet', [Optional()],
                                choices=[('F',u'Acceso Total'),
                                         ('R', u'Acceso con restricciones'),
                                         ('L', u'Solo navegación local')])
    internet_quota = DecimalField('Cuota para Internet en UM')
    socialnetwork_quota = DecimalField('% de la cuota utilizable para redes sociales')
    email_type = SelectField(u'Tipo de cuenta de correo', choices=[('F',u'Sin restrcciones'),
                                                                   ('R', u'Envío y recepción restringidos (.cu)'),
                                                                   ('L', u'Solo correo local')])
    email_quota = DecimalField('Cuota de correo en UM')
    dansguardian_filter = IntegerField(u'Número del filtro de contenido')


class UserAdd(UserProfileEdit):
    base = None
    password = PasswordField(u'Contraseña', [DataRequired()])
    password_confirm = PasswordField(u'Repetir contraseña',
                                     [DataRequired(),
                                      EqualTo('password',
                                              message=u'Las contraseñas deben coincidir')])


class UserAddExtraFields(UserAdd):
    manual = BooleanField(label="Usuario Manual", default="checked")
    person_type = SelectField(label="Tipo de Persona", choices=[('Worker', "Trabajador"), ('Student', "Estudiante")])
    dni = StringField(label='Carné Identidad', validators=[DataRequired()])


class PasswordChange(FlaskForm):
    password = PasswordField(u'Nueva Contraseña', [DataRequired()])
    password_confirm = PasswordField(u'Repetir Nueva Contraseña',
                                     [DataRequired(),
                                      EqualTo('password',
                                              message=u'Las contraseñas deben coincidir')])


class PasswordChangeUser(PasswordChange):
    oldpassword = PasswordField(u'Contraseña actual', [DataRequired()])


def init(app):
    @app.route('/users/+add', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_add():
        title = "Adicionar Usuario"

        if not UserAdd.base:
            UserAdd.base = request.args.get('base')

        base = UserAdd.base
        print(base, "fist base")

        if g.extra_fields:
            form = UserAddExtraFields(request.form)
        else:
            form = UserAdd(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         ('pager', form.category),
                         (None, form.password),
                         (None, form.password_confirm),
                         ('userAccountControl', form.uac_flags)]
        if g.extra_fields:
            extra_field_mapping = [('cUJAEPersonExternal', form.manual),
                                   ('cUJAEPersonType', form.person_type),
                                   ('cUJAEPersonDNI', form.dni)]
            field_mapping += extra_field_mapping

        form.visible_fields = [field[1] for field in field_mapping]
        form.uac_flags.choices = [(key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]

        if form.validate_on_submit():
            try:
                # Default attributes
                upn = "%s@%s" % (form.user_name.data, g.ldap['domain'])
                attributes = {'objectClass': [b'top', b'person', b'organizationalPerson', b'user', b'inetOrgPerson'],
                              'UserPrincipalName': [upn.encode('utf-8')],
                              'accountExpires': [b"0"],
                              'lockoutTime': [b"0"],
                              }

                for attribute, field in field_mapping:
                    if attribute == 'userAccountControl':
                        current_uac = 512
                        for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                            if flag[1] and key in field.data:
                                current_uac += key
                        attributes[attribute] = [str(current_uac).encode('utf-8')]
                    elif attribute and field.data:
                        if isinstance(field, BooleanField):
                            if field.data:
                                attributes[attribute] = 'TRUE'.encode('utf-8')
                            else:
                                attributes[attribute] = 'FALSE'.encode('utf-8')
                        else:
                            attributes[attribute] = [field.data.encode('utf-8')]
                if 'sn' in attributes:
                    attributes['displayName'] = attributes['givenName'][0].decode('utf-8') + " " + attributes[
                                                                                                'sn'][0].decode('utf-8')
                    attributes['displayName'] = [attributes['displayName'].encode('utf-8')]
                else:
                    attributes['displayName'] = attributes['givenName']

                ldap_create_entry("cn=%s,%s" % (form.user_name.data, base), attributes)
                ldap_change_password(None, form.password.data, form.user_name.data)
                flash(u"Usuario creado con éxito.", "success")
                return redirect(url_for('user_overview',
                                        username=form.user_name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
            print(form.errors)
            flash("Some fields failed validation.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Adicionar Usuario",
                               parent=url_for('tree_base'))

    @app.route('/user/<username>', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_overview(username):
        title = "Detalles del Usuario - %s" % username

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        admin = ldap_in_group("Domain Admins")
        logged_user = g.ldap['username']
        
        if logged_user == user['sAMAccountName'] or admin:

            identity_fields = [('givenName', "Nombre"),
                               ('sn', "Apellidos"),
                               ('displayName', "Nombre Completo"),
                               ('name', "Nombre del Registro"),
                               ('sAMAccountName', "Nombre de Usuario"),
                               ('mail', u"Dirección de Correo")]

            if 'title' in user:
                identity_fields.append(('title', "Ocupación"))
            # TODO: CUJAE specific, Remove for master
            if 'pager' in user:
                identity_fields.append(('pager', "Categoría"))
            if 'telephoneNumber' in user:
                identity_fields.append(('telephoneNumber', "Teléfono"))

            group_fields = [('sAMAccountName', "Nombre"),
                            ('description', u"Descripción")]

            user = ldap_get_user(username=username)
            group_details = [ldap_get_group(group, 'distinguishedName')
                            for group in ldap_get_membership(username)]

            groups = sorted(group_details, key=lambda entry:
                            entry['sAMAccountName'])

            siccip_data = None
            if 'pager' in user:
                siccip_data = get_parsed_pager_attribute(user['pager'])
                print(siccip_data)

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
                               group_fields=group_fields, admin=admin, groups=groups, siccip_data=siccip_data,
                               parent=parent, uac_values=LDAP_AD_USERACCOUNTCONTROL_VALUES)

    @app.route('/user/<username>/+changepw', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_changepw(username):
        title = u"Cambiar contraseña"

        if not ldap_user_exists(username=username):
            abort(404)

        admin = ldap_in_group("Domain Admins")
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
    @ldap_auth("Domain Admins")
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
    @ldap_auth("Domain Admins")
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
                         ('pager', form.category),
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
                            ldap_update_attribute(user['distinguishedName'], "sAMAccountName", value)
                            ldap_update_attribute(user['distinguishedName'], "userPrincipalName",
                                                  "%s@%s" % (value, g.ldap['domain']))
                            # Finish by renaming the whole record
                            # TODO: refactor this to use rename_s instead of update
                            # ldap_update_attribute(user['distinguishedName'], "cn", value)
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
            form.uac_flags.data = [key for key, flag in
                                   LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                   if (flag[1] and
                                       user['userAccountControl'] & key)]

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-siccip', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
    def user_edit_siccip(username):
        title = u"Editar Configuración SICC-IP"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        pager = user['pager'][0] if 'pager' in user else None
        form = SICCIPEdit(request.form)
        field_mapping = [       #('internet_type', form.internet_type),
                         ('internet_quota', form.internet_quota),
                         ('socialnetwork_quota', form.socialnetwork_quota),
                         ('dansguardian_filter', form.dansguardian_filter),
                         ('email_type', form.email_type),
                         ('email_quota', form.email_quota)]

        form.visible_fields = [field[1] for field in field_mapping]

        if form.validate_on_submit():
            try:
                internet_type = 'F'
                new_pager = 'I%s%f_%f|E%s%f|D%d' % (internet_type, form.internet_quota.data,
                                                 form.socialnetwork_quota.data,
                                                 form.email_type.data, form.email_quota.data,
                                                 form.dansguardian_filter.data)
                if pager != new_pager:
                    ldap_update_attribute(user['distinguishedName'], "pager", new_pager)
                    print(new_pager)

                flash(u"Perfil actualizado con éxito.", "success")
                return redirect(url_for('user_overview',
                                        username=username))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash(u"Falló la validación de los datos.", "error")

        if not form.is_submitted():
            if pager:
                siccip_data = get_parsed_pager_attribute(pager)
                if siccip_data is not None:
                    form.internet_type.data = siccip_data['internet_type']
                    form.internet_quota.data = siccip_data['internet_quota']
                    form.socialnetwork_quota.data = siccip_data['socialnetwork_quota']
                    form.email_type.data = siccip_data['email_type']
                    form.email_quota.data = siccip_data['email_quota']
                    form.dansguardian_filter.data = siccip_data['dansguardian_filter']

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview',
                                              username=username))


    @app.route('/user/<username>/+edit-ssh', methods=['GET', 'POST'])
    @ldap_auth("Domain Admins")
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


    # @app.route('/user/<username>/+edit-groups', methods=['GET', 'POST'])
    # @ldap_auth("Domain Admins")
    # def user_edit_groups(username):
    #     title = "Editar pertenencia a Grupos"
    #
    #     if not ldap_user_exists(username=username):
    #         abort(404)
    #
    #     user = ldap_get_user(username=username)
    #
    #     form = UserGroupEdit(request.form)
    #     form.visible_fields = [form.ssh_keys]
    #
    #     if form.validate_on_submit():
    #         try:
    #             ldap_update_attribute(user['distinguishedName'],
    #                                   'sshPublicKey', new_entries,
    #                                   'ldapPublicKey')
    #             flash(u"Pertenencia a grupos modificada con éxito.", "success")
    #             return redirect(url_for('user_overview', username=username))
    #         except ldap.LDAPError as e:
    #             e = dict(e.args[0])
    #             flash(e['info'], "error")
    #     elif form.errors:
    #         flash(u"Falló la validación de los datos.", "error")
    #
    #     if not form.is_submitted():
    #         if 'sshPublicKey' in user:
    #             form.ssh_keys.data = "\n".join(user['sshPublicKey'])

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Salvar los cambios",
                               parent=url_for('user_overview', username=username))
