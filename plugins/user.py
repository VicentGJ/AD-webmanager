from flask import json
from flask.json import jsonify
from flask.wrappers import Response
from werkzeug.exceptions import HTTPException
from libs.common import iri_for as url_for
from settings import Settings
from flask import abort, flash, g, render_template, redirect, request, session
from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectMultipleField, TextAreaField, \
    StringField, SelectField, DecimalField, IntegerField, BooleanField
from wtforms.validators import DataRequired,  EqualTo, Optional, Length
from datetime import datetime
from pytz import timezone
import base64

from libs.ldap_func import ldap_auth, ldap_change_password, \
    ldap_create_entry, ldap_delete_entry, ldap_get_user, \
    ldap_get_membership, ldap_get_group, ldap_in_group, ldap_get_entry_simple, ldap_rename_entry, \
    ldap_update_attribute, ldap_user_exists, ldap_get_entries, LDAP_AD_USERACCOUNTCONTROL_VALUES

from libs.common import get_parsed_pager_attribute

import ldap

def init(app):
    @app.route('/user/+add', methods=['POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_add():
        try:
            data: dict = request.json
            base = data["base"]
            password = data["unicodePwd"]
            data.pop("base")
            data.pop("unicodePwd")
            # Default attributes
            upn = "%s@%s" % (data["sAMAccountName"], g.ldap['domain'])
            attributes = {
                'objectClass': [b'top', b'person', b'organizationalPerson', b'user', b'inetOrgPerson'],
                'UserPrincipalName': [upn.encode('utf-8')],
                'accountExpires': [b"0"],
                'lockoutTime': [b"0"],
            }
            for attribute, field in data.items():
                if attribute == 'userAccountControl':
                    current_uac = 512
                    for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                        if flag[1] and key in field:
                            current_uac += key
                    attributes[attribute] = [str(current_uac).encode('utf-8')]
                elif attribute and field:
                    if isinstance(field, bool):
                        if field.data:
                            attributes[attribute] = 'TRUE'.encode('utf-8')
                        else:
                            attributes[attribute] = 'FALSE'.encode('utf-8')
                    else:
                        attributes[attribute] = [field.encode('utf-8')]
            if 'sn' in attributes:
                attributes['displayName'] = attributes['givenName'][0].decode('utf-8') + " " + attributes[
                                                                                                'sn'][0].decode('utf-8')
                attributes['displayName'] = [attributes['displayName'].encode('utf-8')]
            else:
                attributes['displayName'] = attributes['givenName']

            ldap_create_entry("cn=%s,%s" % (data["sAMAccountName"], base), attributes)
            ldap_change_password(None, password, data["sAMAccountName"])
            return jsonify({"response": "ok"}) # TODO: Improve this
        except ldap.LDAPError as e:
           return jsonify({"response": str(e)})
        except KeyError as e:
           print(e)
           return jsonify({"response": "Missing key {0}".format(str(e))})

    @app.route('/user/<username>', methods=['GET'])
    @ldap_auth("Domain Users")
    def user_overview(username):
        title = "Detalles del Usuario - %s" % username

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        admin = ldap_in_group(Settings.ADMIN_GROUP)
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
            if 'telephoneNumber' in user:
                identity_fields.append(('telephoneNumber', "Teléfono"))

            if Settings.USER_ATTRIBUTES:
                for item in Settings.USER_ATTRIBUTES:
                    if item[0] in user:
                        if len(item) == 3 and item[2] == 'time':
                            datetime_field = (user[item[0]][6:8] + '/' + user[item[0]][4:6] + '/' + user[item[0]][0:4] 
                                            + ' ' + user[item[0]][8:10] + ':' + user[item[0]][10:12] + ':' 
                                            + user[item[0]][12:14] )
                            datetime_field = datetime.strptime(datetime_field, '%d/%m/%Y %H:%M:%S')
                            user[item[0]] = datetime_field.astimezone(timezone(Settings.TIMEZONE))
                        if item[0] == 'jpegPhoto':
                            imgbase64 = base64.b64encode(user[item[0]]).decode()
                            user[item[0]] = 'data:image/jpeg;base64,' + imgbase64
                        identity_fields.append((item[0], item[1])) 

            group_fields = [('sAMAccountName', "Nombre"),
                            ('description', u"Descripción")]

            user: dict = ldap_get_user(username=username)
            if 'jpegPhoto' in user:
                user.pop('jpegPhoto')
            group_details = []
            for group in ldap_get_membership(username):
                group_details.append(ldap_get_group(group, 'distinguishedName'))
            # group_details = [ldap_get_group(group, 'distinguishedName') for group in ldap_get_membership(username)]

            group_details = list(filter(None, group_details))

            groups = sorted(group_details, key=lambda entry: entry['sAMAccountName'] )

            siccip_data = None
            if 'pager' in user:
                siccip_data = get_parsed_pager_attribute(user['pager'])
                print(siccip_data)

            available_groups = ldap_get_entries(ldap_filter="(objectclass=group)", scope="subtree")
            group_choices = [("_","Seleccione un Grupo")]
            for group_entry in available_groups:
                if not ldap_in_group(group_entry['sAMAccountName'], username):
                    group_choices += [(group_entry['distinguishedName'], group_entry['sAMAccountName'])]

            parent = ",".join(user['distinguishedName'].split(',')[1:])
        
        else:
            abort(401)

        return jsonify({"user": user, "groups": groups, "siccip_data": siccip_data})

    @app.route('/user/<username>/+changepw', methods=['POST'])
    @ldap_auth("Domain Users")
    def user_changepw(username):

        if not ldap_user_exists(username=username):
            abort(404)

        admin = ldap_in_group(Settings.ADMIN_GROUP)

        try:
            data = request.json
            if username != g.ldap['username'] and admin:
                ldap_change_password(None, data["new_password"],
                                     username=username)
            else:
                ldap_change_password(None, data["old_password"],
                                     data["new_password"], username=username)
            return jsonify({"response": "success"})
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify(e)
        except KeyError as e:
           print(e)
           return jsonify({"response": "Missing key {0}".format(str(e))})

    @app.route('/user/<username>', methods=['DELETE'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_delete(username):
        title = "Borrar Usuario"

        if not ldap_user_exists(username=username):
            abort(404)

        try:
            user = ldap_get_user(username=username)
            ldap_delete_entry(user['distinguishedName'])
            return jsonify({"response": "success"})
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify(e)

    @app.route('/user/<username>', methods=['PUT'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_edit_profile(username):
        title = "Editar usuario"

        if not ldap_user_exists(username=username):
            abort(404)

        user = ldap_get_user(username=username)
        data = request.json
        
        try:
            for attribute, field in data.items():
                value = field
                given_name = user.get('givenName')
                last_name = user.get('lastName')
                if value != user.get(attribute):
                    if attribute == 'cn':
                        ldap_rename_entry(user['distinguishedName'], 'cn', value)
                        user = ldap_get_user(value, 'cn')
                    elif attribute == 'sAMAccountName':
                        # Rename the account
                        ldap_update_attribute(user['distinguishedName'], "sAMAccountName", value)
                        ldap_update_attribute(user['distinguishedName'], "userPrincipalName",
                                                  "%s@%s" % (value, g.ldap['domain']))
                        user = ldap_get_user(value)
                    elif attribute == 'userAccountControl':
                        current_uac = 512
                        for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                            if flag[1] and key in field:
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
                    else:
                        ldap_update_attribute(user['distinguishedName'], attribute, value)

            return jsonify({"response": "success"})
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify(e)
