from settings import Settings
from flask import request, g
from datetime import datetime
from pytz import timezone
from libs.ldap_func import (
    ldap_change_password, ldap_create_entry, ldap_get_user, ldap_in_group,
    ldap_get_membership, _ldap_authenticate, ldap_user_exists,
    LDAP_AD_USERACCOUNTCONTROL_VALUES, ldap_change_password, ldap_create_entry,
    ldap_delete_entry, ldap_rename_entry, ldap_update_attribute,
)
from libs.utils import (
    single_entry_only_selected_fields, fields_cleaning,
    error_response, simple_success_response, decode_ldap_error
)
from libs.logs import logs
import jwt
from datetime import timedelta
import os
from ldap import LDAPError


@logs([])
def s_get_jwt():
    auth = request.authorization
    groups = ldap_get_membership(auth.username)
    if groups is None:
        return _ldap_authenticate()

    encoded = jwt.encode({
        'sub': auth.username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=15),
        "iss": "ad-webmanager",
        'claims': {
            'groups': groups
        }

    }, os.getenv("JWT_SECRET"), os.getenv("JWT_ALGO"))

    response = {'access_token': encoded}
    return simple_success_response(response)


@logs(['value'])
def s_user_overview(current_user, value):

    if request.args.get('key'):
        key = request.args.get('key')
    else:
        key = 'sAMAccountName'

    fields = request.args.get('fields')
    if not ldap_user_exists(value=value, key=key):
        error = "User not found"
        response = error_response(
                method="s_user_overview",
                username=value,
                error=error,
                status_code=200,
        )
        return response

    user = ldap_get_user(value, key)
    admin = ldap_in_group(Settings.ADMIN_GROUP)
    logged_user = current_user

    if logged_user == user['sAMAccountName'] or admin:
        if user["userAccountControl"]:
            for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                if flag[1] and key == user["userAccountControl"]:
                    user["userAccountControl"] = flag[0]

        if hasattr(Settings, "TIMEZONE"):
            datetime_field = (
                user["whenChanged"][6:8] + '/' +
                user["whenChanged"][4:6] + '/' +
                user["whenChanged"][0:4] + ' ' +
                user["whenChanged"][8:10] + ':' +
                user["whenChanged"][10:12] + ':' +
                user["whenChanged"][12:14]
            )
            datetime_field = datetime.strptime(
                datetime_field, '%d/%m/%Y %H:%M:%S'
            )
            user["whenChanged"] = datetime_field.astimezone(
                timezone(Settings.TIMEZONE)
            )

            datetime_field = (
                user["whenCreated"][6:8] + '/' +
                user["whenCreated"][4:6] + '/' +
                user["whenCreated"][0:4] + ' ' +
                user["whenCreated"][8:10] + ':' +
                user["whenCreated"][10:12] + ':' +
                user["whenCreated"][12:14]
            )
            datetime_field = datetime.strptime(
                datetime_field, '%d/%m/%Y %H:%M:%S'
            )
            user["whenCreated"] = datetime_field.astimezone(
                timezone(Settings.TIMEZONE)
            )

        if 'jpegPhoto' in user:
            user.pop('jpegPhoto')
        user = single_entry_only_selected_fields(fields, user)
        fields_cleaning(user)

    else:
        response = error_response(
            method="s_user_overview",
            username=current_user,
            error="Not enough credentials",
            status_code=401,
        )
        return response

    return simple_success_response(user)


@logs([])
def s_user_add(current_user):
    try:
        data: dict = request.json
        base = data["base"]
        password = data["unicodePwd"]
        data.pop("base")
        data.pop("unicodePwd")
        # Default attributes
        upn = "%s@%s" % (data["sAMAccountName"], g.ldap['domain'])
        attributes = {
            'objectClass': [
                b'top',
                b'person',
                b'organizationalPerson',
                b'user',
                b'inetOrgPerson'
            ],
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

    except LDAPError as e:
        error = decode_ldap_error(e)
        response = error_response(
            method="s_user_add",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response

    except KeyError as e:
        error = "Missing key {0}".format(str(e))
        response = error_response(
            method="s_user_add",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response


@logs(['username'])
def s_user_changepw(current_user, username):

    if not ldap_user_exists(value=username):
        error = "User not found"
        response = error_response(
            method="s_user_changepw",
            username=current_user,
            error=error,
            status_code=404,
        )
        return response

    admin = ldap_in_group(Settings.ADMIN_GROUP)

    try:
        data = request.json
        if username != g.ldap['username'] and admin:
            ldap_change_password(None, data["new_password"], username=username)
        else:
            ldap_change_password(
                None,
                data["old_password"],
                data["new_password"],
                username=username,
            )
        return simple_success_response("Success")

    except LDAPError as e:
        error = decode_ldap_error(e)
        response = error_response(
            method="s_user_changepw",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response

    except KeyError as e:
        error = "Missing key {0}".format(str(e))
        response = error_response(
            method="s_user_changepw",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response


@logs(['username'])
def s_user_delete(current_user, username):

    if not ldap_user_exists(value=username):
        error = "User not found"
        response = error_response(
            method="s_user_delete",
            username=current_user,
            error=error,
            status_code=404,
        )
        return response

    try:
        user = ldap_get_user(username)
        ldap_delete_entry(user['distinguishedName'])

        return simple_success_response("Success")

    except LDAPError as e:
        error = decode_ldap_error(e)
        response = error_response(
            method="s_user_delete",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response


@logs(['username'])
def s_user_edit_profile(current_user, username):

    if not ldap_user_exists(username=username):
        error = "User not found"
        response = error_response(
            method="s_user_edit_profile",
            username=current_user,
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

    except LDAPError as e:
        error = decode_ldap_error(e)
        response = error_response(
            method="s_user_edit_profile",
            username=current_user,
            error=error,
            status_code=500,
        )
        return response
