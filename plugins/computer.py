import ldap, logging
from flask import abort, flash, g, redirect, render_template, request
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from libs.common import (flash_password_errors, get_attr, get_encoded_list,
                         get_parsed_pager_attribute, get_valid_macs)
from libs.common import iri_for as url_for
from libs.common import namefrom_dn, password_is_valid
from libs.ldap_func import (LDAP_AD_USERACCOUNTCONTROL_VALUES, ldap_auth,
                            ldap_change_password, ldap_create_entry,
                            ldap_delete_entry, ldap_get_all_users,
                            ldap_get_entries, ldap_get_entry_simple,
                            ldap_get_group, ldap_get_membership, ldap_get_user,
                            ldap_in_group, ldap_update_attribute,
                            ldap_user_exists)
from settings import Settings
from wtforms import (BooleanField, DecimalField, EmailField, IntegerField,
                     PasswordField, SelectField, SelectMultipleField,
                     StringField, TextAreaField)
from wtforms.validators import DataRequired, EqualTo, Length, Optional

class ComputerEdit(FlaskForm):
    user_name = StringField('Username', [DataRequired(), Length(max=20)])
    location = StringField('Location')
    machine_role = StringField('Machine Role')
    managed_by = StringField('Managed by')
    uac_flags = SelectMultipleField('Flags', coerce=int)

def init(app):
    @app.route('/computer/<username>', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def computer_overview(username):
        title = "Computer details - {0}".format(username)

        if not ldap_user_exists(username=username):
            flash(f"The computer: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        user = ldap_get_user(username=username)
        admin = ldap_in_group(Settings.ADMIN_GROUP)
        logged_user = g.ldap['username']
        if logged_user == user['sAMAccountName'] or admin:

            identity_fields = [
                ('displayName', "Name"),
                ('name', "Registry Name"),
                ('sAMAccountName', "Username"),
                ('operatingSystem', "Operating System"),
                ('networkAddress', "Network Address"),
                ('machineRole', "Machine Role"),
                ('managedBy', "Managed by")
            ]
            group_fields = [('sAMAccountName', "Name"),
                                ('description', u"Description")]

            group_details = []
            group_membership = ldap_get_membership(username)
            for group in group_membership:
                group_details.append(ldap_get_group(
                    group, 'distinguishedName'))

            group_details = list(filter(None, group_details))

            groups = sorted(
                group_details, key=lambda entry: entry['sAMAccountName'])

            available_groups = ldap_get_entries(
                ldap_filter="(objectclass=group)", scope="subtree")
            group_choices = [("_", "Select a Group")]

            for group_entry in available_groups:
                if not group_entry['distinguishedName'] in group_membership:
                    # if not ldap_in_group(group_entry['sAMAccountName'], username):
                    group_choices += [(group_entry['distinguishedName'],
                                       group_entry['sAMAccountName'])]

            class UserAddGroup(FlaskForm):
                available_groups = SelectField('Groups')

            form = UserAddGroup(request.form)
            form.available_groups.choices = group_choices

            if not form.is_submitted():
                form.available_groups.data = "_"

            if form.validate_on_submit():
                try:
                    group_to_add = form.available_groups.data
                    if group_to_add == "_":
                        flash(
                            u"You must choose a group from the drop-down list.", "error")
                    else:
                        group = ldap_get_entry_simple(
                            {'objectClass': 'group', 'distinguishedName': group_to_add})
                        if 'member' in group:
                            entries = set(group['member'])
                        else:
                            entries = set()
                        entries.add(user['distinguishedName'])
                        ldap_update_attribute(
                            group_to_add, "member", list(entries))
                        flash(u"User successfully added to group.", "success")
                    return redirect(url_for('user_overview', username=username))
                except ldap.LDAPError as e:
                    e = dict(e.args[0])
                    flash(e['info'], "error")
            elif form.errors:
                flash(u"Data validation failed.", "error")

            parent = ",".join(user['distinguishedName'].split(',')[1:])

        else:
            abort(401)
        name = namefrom_dn(parent)
        return render_template("pages/user_overview_es.html", g=g, title=title, form=form,
                               user=user, identity_fields=identity_fields,
                               group_fields=group_fields, admin=admin, groups=groups,
                               parent=parent, uac_values=LDAP_AD_USERACCOUNTCONTROL_VALUES, name=name)
    
    @app.route('/computer/<username>/+edit-profile', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def computer_edit_profile(username):
        title = "Edit Computer"
        if not ldap_user_exists(username):
            flash(f"The computer: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))
        form = ComputerEdit(request.form)
        user = ldap_get_user(username=username)
        attr_compilation = get_attr(user)
        users = ldap_get_all_users()
        field_mapping = [
            ('sAMAccountName', form.user_name),
            ('location', form.location),
            ('machineRole', form.machine_role),
            ('managedBy', form.managed_by),
            ('userAccountControl', form.uac_flags)
        ]
        form.uac_flags.choices = [
            (key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]
        form.visible_fields = [field[1] for field in field_mapping]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    has_attribute = user.get(attribute) != None
                    if value != user.get(attribute) or not has_attribute:
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(
                                user['distinguishedName'], "sAMAccountName", value)
                            ldap_update_attribute(user['distinguishedName'], "userPrincipalName",
                                                  "%s@%s" % (value, g.ldap['domain']))
                            # Finish by renaming the whole record
                            # TODO: refactor this to use rename_s instead of update
                            rdn = f'CN={value}'
                            ldap_update_attribute(
                                user['distinguishedName'], "distinguishedName", rdn)
                            user = ldap_get_user(value)
                        elif attribute == 'userAccountControl':
                            current_uac = 512
                            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                                if flag[1] and key in field.data:
                                    current_uac += key
                            ldap_update_attribute(
                                user['distinguishedName'], attribute, str(current_uac))
                        else:
                            ldap_update_attribute(
                                user['distinguishedName'], attribute, value)
                flash(u"Profile updated successfully.", "success")
                return redirect(url_for('computer_overview', username=form.user_name.data))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
                logging.exception("Got an exception")
            except Exception as e:
                flash(e, 'error')
                logging.exception("Got an exception")
        elif form.errors:
            flash(u"Data validation failed.", "error")
  
        return render_template("forms/basicform.html", form=form, title=title, 
                               parent=url_for('computer_overview', username=username))