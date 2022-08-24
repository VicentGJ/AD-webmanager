import base64
from io import BytesIO
import logging

import ldap
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
from PIL import Image
from settings import Settings
from wtforms import (BooleanField, DecimalField, EmailField, IntegerField,
                     PasswordField, SelectField, SelectMultipleField,
                     StringField, TextAreaField)
from wtforms.validators import DataRequired, EqualTo, Length, Optional


class UserSSHEdit(FlaskForm):
    ssh_keys = TextAreaField('SSH keys')


class UserAddGroup(FlaskForm):
    available_groups = SelectField('Groups')


class UserProfileEdit(FlaskForm):
    profile_pic = FileField('Profile Picture')
    first_name = StringField('Name', [DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', [Length(max=64)])
    user_name = StringField('Username', [DataRequired(), Length(max=20)])
    mail = EmailField(u'Email Address', [Length(max=256)])
    alias = EmailField('Other Email Addresses', [Length(max=256)])
    manager = StringField('Manager')
    address = TextAreaField('Address')
    phones_home = StringField('Home Phones')
    phones_mobile = StringField('Mobile Phones')
    phones_office = StringField('Office Phones')
    employee_id = StringField('Employee ID')
    role = StringField('Role')
    mac_address = StringField('MAC Address')
    uac_flags = SelectMultipleField('Flags', coerce=int)



class SICCIPEdit(FlaskForm):
    internet_type = SelectField(u'Internet access type', [Optional()],
                                choices=[('F',u'Acceso Total'),
                                         ('R', u'Restricted access'),
                                         ('L', u'Local navigation only')])
    internet_quota = DecimalField('Quota for Internet in UM')
    socialnetwork_quota = DecimalField('% of the usable quota for social networks')
    email_type = SelectField(u'Email account type', choices=[('F',u'No restrictions'),
                                                             ('R', u'Restricted sending and receiving'),
                                                             ('L', u'Local mail only')])
    email_quota = DecimalField('Mail quota in UM')
    dansguardian_filter = IntegerField(u'Content filter number')


class UserAdd(UserProfileEdit):
    base = None
    password = PasswordField(u'Password', [DataRequired()])
    password_confirm = PasswordField(u'Repeat password',
                                     [DataRequired(),
                                      EqualTo('password',
                                              message=u'Passwords must match')])


class PasswordChange(FlaskForm):
    password = PasswordField(u'New Password', [DataRequired()])
    password_confirm = PasswordField(u'Repeat New Password',
                                     [DataRequired(),
                                      EqualTo('password',
                                              message=u'Passwords must match')])


class PasswordChangeUser(PasswordChange):
    oldpassword = PasswordField(u'Current password', [DataRequired()])


class GifNotAllowed(Exception):
    pass

def init(app):
    @app.route('/users/+add/<base>', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_add(base):
        title = "Add User"
        user_list = ldap_get_all_users()
        form = UserAdd(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('sn', form.last_name),
                         ('sAMAccountName', form.user_name),
                         ('jpegPhoto', form.profile_pic),
                         ('mail', form.mail),
                         ('otherMailbox', form.alias),
                         ('manager', form.manager),
                         ('streetAddress', form.address),
                         ('otherHomePhone', form.phones_home),
                         ('otherMobile', form.phones_mobile),
                         ('otherTelephone', form.phones_office),
                         ('employeeID', form.employee_id),
                         ('title', form.role),
                         ('macAddress', form.mac_address),
                         (None, form.password),
                         (None, form.password_confirm),
                         ('userAccountControl', form.uac_flags),
                         ]
        
        form.visible_fields = [field[1] for field in field_mapping]
        form.uac_flags.choices = [(key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]
        if form.validate_on_submit():
            try:
                # Default attributes
                upn = "%s@%s" % (form.user_name.data, g.ldap['domain'])
                attributes = {'objectClass': [b'top', b'ieee802Device', b'person', b'organizationalPerson', b'user', b'inetOrgPerson'],
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
                    elif attribute == 'otherMailbox' or attribute == 'otherHomePhone' or \
                            attribute == 'otherMobile' or attribute == 'otherTelephone':
                        list_to_encode = list(filter(None, request.form.getlist(attribute)))
                        if len(list_to_encode)>0:
                            attributes[attribute] = get_encoded_list(list_to_encode)
                    elif attribute == 'macAddress':
                        list_to_encode = list(filter(None, request.form.getlist(attribute)))
                        if len(list_to_encode):
                            valid_macs = get_valid_macs(list_to_encode)
                            attributes[attribute] = get_encoded_list(valid_macs)
                    elif attribute == 'manager' and field.data:
                        manager = ldap_get_user(field.data)
                        if manager:
                            attributes[attribute] = manager['distinguishedName'].encode('utf-8')
                        else:
                            raise Exception("That manager doesn't exists")
                    elif attribute == 'jpegPhoto' and request.files is not None:
                        data = request.files
                        data_dict = data.to_dict(flat=False)
                        file = data_dict['profile_photo'][0]
                        if(file.filename):
                                image = Image.open(file)
                                if(image.format == 'GIF'):
                                    raise GifNotAllowed('No gifs allowed in user profile picture')
                                jpeg_binary = BytesIO()
                                rgb_image = image.convert('RGB')
                                rgb_image.save(jpeg_binary,format='JPEG')
                                attributes[attribute] = jpeg_binary.getvalue()
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
                password_validation = password_is_valid(form.password.data)
                if not password_validation:
                    ldap_create_entry("cn=%s,%s" % (form.user_name.data, base), attributes)
                    ldap_change_password(None, form.password.data, form.user_name.data)
                    flash(u"User created successfully.", "success")
                    created_user = ldap_get_user(username=form.user_name.data)
                    return redirect(url_for('user_overview', username=form.user_name.data))
                else:
                    flash_password_errors(password_validation)
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
                logging.exception("Got an exception")
            except GifNotAllowed as e:
                flash(e,'error')
                logging.exception("Got an exception")
            except Exception as e:
                flash(e,'error')
                logging.exception("Got an exception")
        elif form.errors:
            flash("Some fields failed validation.", "error")
        
        return render_template("forms/user_add.html", form=form, title=title,
                               action="Add User", user_list=user_list,
                               parent=url_for('tree_base'))

    @app.route('/user/<username>', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_overview(username):
        title = "User details - %s" % username

        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        user = ldap_get_user(username=username)
        admin = ldap_in_group(Settings.ADMIN_GROUP)
        logged_user = g.ldap['username']
        if logged_user == user['sAMAccountName'] or admin:

            identity_fields = [('givenName', "Name"),
                               ('sn', "Last Name"),
                               ('displayName', "Full Name"),
                               ('name', "Registry Name"),
                               ('sAMAccountName', "Username"),
                               ('mail', u"Email address")]

            if 'title' in user:
                identity_fields.append(('title', "Occupation"))
            if 'telephoneNumber' in user:
                identity_fields.append(('telephoneNumber', "Telephone"))

            if 'jpegPhoto' in user:
                imgbase64 = base64.b64encode(user['jpegPhoto']).decode()
                user['jpegPhoto'] = 'data:image/jpeg;base64,' + imgbase64
                identity_fields.append(('Profile Photo', 'jpegPhoto'))

            group_fields = [('sAMAccountName', "Name"),
                            ('description', u"Description")]

            group_details = []
            group_membership = ldap_get_membership(username)
            for group in group_membership:
                group_details.append(ldap_get_group(group, 'distinguishedName'))

            group_details = list(filter(None, group_details))

            groups = sorted(group_details, key=lambda entry: entry['sAMAccountName'] )

            available_groups = ldap_get_entries(ldap_filter="(objectclass=group)", scope="subtree")
            group_choices = [("_","Select a Group")]

            for group_entry in available_groups:
                if not group_entry['distinguishedName'] in group_membership:
                #if not ldap_in_group(group_entry['sAMAccountName'], username):
                    group_choices += [(group_entry['distinguishedName'], group_entry['sAMAccountName'])]

            form = UserAddGroup(request.form)
            form.available_groups.choices = group_choices

            if not form.is_submitted():
                form.available_groups.data = "_"

            if form.validate_on_submit():
                try:
                    group_to_add = form.available_groups.data
                    if group_to_add == "_":
                        flash(u"You must choose a group from the drop-down list.", "error")
                    else:
                        group = ldap_get_entry_simple({'objectClass': 'group', 'distinguishedName': group_to_add})
                        if 'member' in group:
                            entries = set(group['member'])
                        else:
                            entries = set()
                        entries.add(user['distinguishedName'])
                        ldap_update_attribute(group_to_add, "member", list(entries))
                        flash(u"User successfully added to group.", "success")
                    return redirect(url_for('user_overview',username=username))
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

    @app.route('/user/<username>/+changepw', methods=['GET', 'POST'])
    @ldap_auth("Domain Users")
    def user_changepw(username):
        title = u"Change Password"

        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        admin = ldap_in_group(Settings.ADMIN_GROUP)

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
                flash(u"The password was changed successfully.", "success")
                return redirect(url_for('user_overview', username=username))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
                flash(u"Data validation failed.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action=u"Change Password",
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_delete(username):
        title = "Delete User"

        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                user = ldap_get_user(username=username)
                ldap_delete_entry(user['distinguishedName'])
                flash(u"User deleted successfully.", "success")
                return redirect(url_for('core_index'))
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
        elif form.errors:
                flash(u"Data validation failed.", "error")

        return render_template("pages/user_delete_es.html", title=title,
                               action="Delete User", form=form,
                               username=username,
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-profile', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_edit_profile(username):
        title = "Edit user"
        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        user = ldap_get_user(username=username)
        attr_compilation = get_attr(user)
        user_list = ldap_get_all_users()
        form = UserProfileEdit(request.form)
        field_mapping = [('givenName', form.first_name),
                         ('jpegPhoto', form.profile_pic),
                         ('sn', form.last_name),
                         ('sAMAccountName', form.user_name),
                         ('mail', form.mail),
                         ('streetAddress', form.address),
                         ('otherMailbox', form.alias),
                         ('otherHomePhone', form.phones_home),
                         ('otherMobile', form.phones_mobile),
                         ('otherTelephone', form.phones_office),
                         ('employeeID', form.employee_id),
                         ('title', form.role),
                         ('macAddress', form.mac_address),
                         ('manager', form.manager),
                         ('userAccountControl', form.uac_flags)]

        form.uac_flags.choices = [(key, value[0]) for key, value in LDAP_AD_USERACCOUNTCONTROL_VALUES.items()]

        form.visible_fields = [field[1] for field in field_mapping]
        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    has_attribute = user.get(attribute) != None
                    if attribute !=  'jpegPhoto':
                        value = field.data
                    else:
                        value = request.files
                    given_name = user.get('givenName')
                    last_name = user.get('sn')
                    if value != user.get(attribute) or not has_attribute:
                        if attribute == 'sAMAccountName':
                            # Rename the account
                            ldap_update_attribute(user['distinguishedName'], "sAMAccountName", value)
                            ldap_update_attribute(user['distinguishedName'], "userPrincipalName",
                                                  "%s@%s" % (value, g.ldap['domain']))
                            # Finish by renaming the whole record
                            # TODO: refactor this to use rename_s instead of update
                            ldap_update_attribute(user['distinguishedName'], "distinguishedName", value)
                            user = ldap_get_user(value)
                        elif attribute == 'userAccountControl':
                            current_uac = 512
                            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                                if flag[1] and key in field.data:
                                    current_uac += key
                            ldap_update_attribute(user['distinguishedName'], attribute, str(current_uac)) 
                        elif attribute == 'givenName':
                            given_name = value
                            ldap_update_attribute(user['distinguishedName'], attribute, value)
                            displayName = given_name + ' ' + last_name
                            ldap_update_attribute(user['distinguishedName'], 'displayName', displayName)
                        elif attribute == 'sn':
                            last_name = value
                            ldap_update_attribute(user['distinguishedName'], attribute, value)
                            displayName = given_name + ' ' + last_name
                            ldap_update_attribute(user['distinguishedName'], 'displayName', displayName)
                        elif attribute == 'otherMailbox' or attribute == 'otherHomePhone' or \
                                attribute == 'otherMobile' or attribute == 'otherTelephone':
                            given_list = list(filter(None, request.form.getlist(attribute)))
                            if len(given_list):
                                ldap_update_attribute(user['distinguishedName'], attribute, given_list)
                            else:
                                ldap_update_attribute(user['distinguishedName'], attribute)
                        elif attribute == 'macAddress':
                            given_list = list(filter(None, request.form.getlist(attribute)))
                            valid_macs = get_valid_macs(given_list)
                            if len(valid_macs):
                                ldap_update_attribute(user['distinguishedName'], attribute, valid_macs)
                            else:
                                ldap_update_attribute(user['distinguishedName'], attribute)
                        elif attribute == 'manager' and value:
                            manager = ldap_get_user(value)
                            if manager:
                                ldap_update_attribute(user['distinguishedName'],attribute,manager['distinguishedName'])
                            else:
                                raise Exception("That manager doesn't exists")
                        elif attribute == 'jpegPhoto':
                            data_dict = value.to_dict(flat=False)
                            file = data_dict['profile_photo'][0]
                            if(file.filename):
                                image = Image.open(file)
                                if(image.format == 'GIF'):
                                    raise GifNotAllowed('No gifs allowed in user profile picture')
                                jpeg_binary = BytesIO()
                                rgb_image = image.convert('RGB')
                                rgb_image.save(jpeg_binary,format='JPEG')
                                ldap_update_attribute(user['distinguishedName'], attribute, jpeg_binary.getvalue())
                        else:
                            ldap_update_attribute(user['distinguishedName'], attribute, value)
                flash(u"Profile updated successfully.", "success")
                return redirect(url_for('user_overview', username=form.user_name.data))

            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")
                logging.exception("Got an exception")
            except GifNotAllowed as e:
                flash(e,'error')
                logging.exception("Got an exception")
            except Exception as e:
                flash(e, 'error')
                logging.exception("Got an exception")
        elif form.errors:
            flash(u"Data validation failed.", "error")

        elif not form.is_submitted():
            form.first_name.data = user.get('givenName')
            form.last_name.data = user.get('sn')
            form.user_name.data = user.get('sAMAccountName')
            form.mail.data = user.get('mail')
            if 'manager' in user.keys():
                managerDN = user.get('manager')
                manager = ldap_get_user(managerDN, key="distinguishedName")
                form.manager.data = manager['sAMAccountName']
            if 'streetAddress' in user.keys():
                form.address.data = user.get('streetAddress')
            if 'employeeID' in user.keys():
                form.employee_id.data = user.get('employeeID')
            if 'title' in user.keys():
                form.role.data = user.get('title')
            attr_compilation = get_attr(user)
            form.uac_flags.data = [key for key, flag in
                                   LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                                   if (flag[1] and
                                       user['userAccountControl'] & key)]
        return render_template("forms/user_edit.html", form=form, title=title,user_list=user_list,
                               action="Save changes",username=username, 
                               othermails=attr_compilation['otherMailbox'],
                               mac_address=attr_compilation['macAddress'],
                               phones_home=attr_compilation['otherHomePhone'],
                               phones_mobile=attr_compilation['otherMobile'],
                               phones_office=attr_compilation['otherTelephone'],
                               profile_pic=attr_compilation['jpegPhoto'],
                               parent=url_for('user_overview',
                                              username=username))

    @app.route('/user/<username>/+edit-siccip', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_edit_siccip(username):
        title = u"Edit SICC-IP Configuration"

        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

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

                flash(u"Profile updated successfully.", "success")
                return redirect(url_for('user_overview',
                                        username=username))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                flash(error, "error")
        elif form.errors:
            flash(u"Data validation failed.", "error")

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
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_edit_ssh(username):
        title = "Edit SSH keys"

        if not ldap_user_exists(username=username):
            flash(f"The user: {username}, doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

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
            flash(u"Data validation failed.", "error")

        if not form.is_submitted():
            if 'sshPublicKey' in user:
                form.ssh_keys.data = "\n".join(user['sshPublicKey'])

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Save changes",
                               parent=url_for('user_overview',
                                              username=username))
