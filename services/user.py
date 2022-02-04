from flask.json import jsonify
from settings import Settings
from flask import request
from datetime import datetime
from pytz import timezone
from libs.ldap_func import (
    ldap_get_user, ldap_in_group,
    ldap_user_exists, LDAP_AD_USERACCOUNTCONTROL_VALUES,
    ldap_get_membership, _ldap_authenticate
)
from libs.utils import (
    single_entry_only_selected_fields, fields_cleaning,
    error_response, simple_success_response
)
from libs.logs import logs
import jwt
from datetime import datetime, timedelta
import os


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
