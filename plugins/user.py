from flask.json import jsonify
from settings import Settings
from flask import abort, g, request
from datetime import datetime
from pytz import timezone
from libs.ldap_func import (
    ldap_auth, ldap_change_password, ldap_create_entry, ldap_delete_entry,
    ldap_get_user, ldap_in_group,
    ldap_rename_entry, ldap_update_attribute,
    ldap_user_exists, LDAP_AD_USERACCOUNTCONTROL_VALUES,
    ldap_get_membership, _ldap_authenticate
)
from libs.utils import (
    single_entry_only_selected_fields, fields_cleaning, decode_ldap_error,
    error_response, simple_success_response, token_required
)
import ldap
from libs.logs import logs
from utils import constants
import jwt
from datetime import datetime, timedelta
from services.user import (
    s_user_overview, s_get_jwt,
)
import os

def init(app):
    @app.route('/user/+add', methods=['POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs([])
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

            ldap_create_entry(
                "cn=%s,%s" % (data["sAMAccountName"], base),
                attributes
            )
            ldap_change_password(None, password, data["sAMAccountName"])

            return simple_success_response("Success")

        except ldap.LDAPError as e:
            error = decode_ldap_error(e)
            response = error_response(
                method="user_add",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

        except KeyError as e:
            error = "Missing key {0}".format(str(e))
            response = error_response(
                method="user_add",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

    @app.route('/jwt', methods=['GET'])
    @ldap_auth("Domain Users")
    def login_jwt():
        return s_get_jwt()

    @app.route('/user/<value>', methods=['GET'])
    @token_required("Domain User")
    def user_overview(current_user, value):
        return s_user_overview(current_user, value)

    @app.route('/user/<username>/+changepw', methods=['POST'])
    @ldap_auth("Domain Users")
    @logs(['username'])
    def user_changepw(username):

        if not ldap_user_exists(value=username):
            error = "User not found"
            response = error_response(
                method="user_changepw",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        admin = ldap_in_group(Settings.ADMIN_GROUP)

        try:
            data = request.json
            if username != g.ldap['username'] and admin:
                ldap_change_password(None, data["new_password"],
                                     username=username)
            else:
                ldap_change_password(None, data["old_password"],
                                     data["new_password"], username=username)
            return simple_success_response("Success")
        except ldap.LDAPError as e:
            error = decode_ldap_error(e)
            response = error_response(
                method="user_changepw",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response
        except KeyError as e:
            error = "Missing key {0}".format(str(e))
            response = error_response(
                method="user_changepw",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

    @app.route('/user/<username>', methods=['DELETE'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def user_delete(username):

        if not ldap_user_exists(value=username):
            error = "User not found"
            response = error_response(
                method="user_delete",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        try:
            user = ldap_get_user(username)
            ldap_delete_entry(user['distinguishedName'])

            return simple_success_response("Success")

        except ldap.LDAPError as e:
            error = decode_ldap_error(e)
            response = error_response(
                method="user_delete",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

    @app.route('/user/<username>', methods=['PUT'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs(['username'])
    def user_edit_profile(username):

        if not ldap_user_exists(username=username):
            error = "User not found"
            response = error_response(
                method="user_edit_profile",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        user = ldap_get_user(username)
        data = request.json
        
        try:
            for attribute, field in data.items():
                value = field
                given_name = user.get('givenName')
                last_name = user.get('lastName')
                if value != user.get(attribute):
                    if attribute == 'cn':
                        ldap_rename_entry(
                            user['distinguishedName'],
                            'cn', 
                            value
                        )
                        user = ldap_get_user(value, 'cn')
                    elif attribute == 'sAMAccountName':
                        # Rename the account
                        ldap_update_attribute(
                            user['distinguishedName'],
                            "sAMAccountName",
                            value
                        )
                        ldap_update_attribute(
                            user['distinguishedName'],
                            "userPrincipalName",
                            "%s@%s" % (value, g.ldap['domain'])
                        )
                        user = ldap_get_user(value)
                    elif attribute == 'userAccountControl':
                        current_uac = 512
                        for key, flag in (
                            LDAP_AD_USERACCOUNTCONTROL_VALUES.items()
                        ):
                            if flag[1] and key in field:
                                current_uac += key
                        ldap_update_attribute(
                            user['distinguishedName'],
                            attribute, str(current_uac)
                        )
                    elif attribute == 'givenName':
                        given_name = value
                        ldap_update_attribute(
                            user['distinguishedName'],
                            attribute,
                            value
                        )
                        displayName = given_name + ' ' + last_name
                        ldap_update_attribute(
                            user['distinguishedName'],
                            'displayName',
                            displayName
                        )
                    elif attribute == 'sn':
                        last_name = value
                        ldap_update_attribute(
                            user['distinguishedName'],
                            attribute,
                            value
                        )
                        displayName = given_name + ' ' + last_name
                        ldap_update_attribute(
                            user['distinguishedName'],
                            'displayName',
                            displayName
                        )
                    else:
                        ldap_update_attribute(
                            user['distinguishedName'],
                            attribute,
                            value
                        )

            return simple_success_response("Success")

        except ldap.LDAPError as e:
            error = decode_ldap_error(e)
            response = error_response(
                method="user_edit_profile",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response
