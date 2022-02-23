from json import loads
from tokenize import String
from ntpath import curdir
from libs.ldap_func import (
    LDAP_AD_USERACCOUNTCONTROL_VALUES, LDAP_AP_PRIMRARY_GROUP_ID_VALUES,
    _ldap_connect, ldap_in_group
)
from utils import constants
from settings import Settings
from libs.logger import log_info, log_error
from utils import constants
from flask import request, g
import jwt
import os
import sqlite3

def multiple_entries_fields_cleaning(function):
    def wrapper(*args, **kwargs):

        result = function(*args, **kwargs)
        if result is not None:
            for entry in result:
                fields_cleaning(entry)
            return result

    return wrapper


def single_entry_fields_cleaning(function):
    def wrapper(*args, **kwargs):

        result = function(*args, **kwargs)
        fields_cleaning(result)
        return result

    return wrapper


def fields_cleaning(entry):
    if 'error' not in entry:
        for attribute, value in entry.items():
            if attribute == "userAccountControl":
                for key, flag in (LDAP_AD_USERACCOUNTCONTROL_VALUES.items()):
                    if flag[1] and key == value:
                        entry[attribute] = flag[0]
                        break

            if attribute == "lastLogon" or \
                attribute == "lastLogonTimestamp" or \
                    attribute == "pwdLastSet":
                entry[attribute] = convert_adtimestamp_to_milliseconds(
                    int(entry[attribute])
                )
            if attribute == "primaryGroupID":
                for key, flag in (LDAP_AP_PRIMRARY_GROUP_ID_VALUES.items()):
                    if key == int(value):
                        entry[attribute] = flag
                        break


def multiple_entry_only_selected_fields(fields, entries):
    if fields is not None:
        fields_list = fields.split(",")
        newEntries = [
            {
                key: entry[key]
                for key in entry
                if key in fields_list
            } for entry in entries
        ]
        newEntries = list(filter(lambda x: len(x) > 0, newEntries))
    else:
        newEntries = entries
    return newEntries


def single_entry_only_selected_fields(fields, entry):

    if fields is not None:
        fields_list = fields.split(",")
        newEntry = {
                key: entry[key]
                for key in entry
                if key in fields_list
            }
    else:
        newEntry = entry
    return newEntry


def convert_adtimestamp_to_milliseconds(timestamp: int):
    """
        This function takes a 18 digit AD timestamp
        and returns the corresponding in milliseconds
    """
    milliseconds = timestamp
    if milliseconds > 0:
        unix_timestamp = (timestamp / 10000000) - 11644473600
        milliseconds = unix_timestamp*1000
    return milliseconds


def decode_ldap_error(e):
    """
        Transform the LDAPError into json and return
        its description
    """
    result = "Unknown error"
    errString = str(e).replace("'", '"')
    error = loads(errString)

    if 'desc' in error:
        result = error['desc']

    return result


def error_response(method, username, error, status_code):
    """
        Create the unauthorize response
    """
    log_error(constants.LOG_EX, method, {
                "error": error,
                "username": username,
            })
    return {"data": None, "error": error}, status_code


def simple_success_response(data):
    """
        Create a simple success response
    """
    return {"data": data, "error": None}, 200


def token_required(group=None):
    def decorator(function):
        def wrapper(*args, **kwargs):
            token = None
            current_user = None
            # jwt is passed in the request header
            if "Authorization" in request.headers:
                token = request.headers["Authorization"].split("Bearer ")
                if len(token) < 2:
                    return {'message': 'Token is missing'}, 401
                token = token[1]
            # return 401 if token is not passed
            if not token:
                return {'message': 'Token is missing'}, 401
                # decoding the payload to fetch the stored details
            decoded = decode_jwt(token)
            if isinstance(decoded, type(String)) is False:
                return decoded
            else:
                current_user = decoded
            
            if group is not None and not ldap_in_group(group, current_user):
                return error_response(
                    method="token_required",
                    username="",
                    error=constants.UNAUTHORIZED,
                    status_code=401,
                )

            return function(current_user, *args, **kwargs)
        wrapper.__name__ = function.__name__
        return wrapper
    return decorator


def expired_token(group=None):
    def decorator(function):
        def wrapper(*args, **kwargs):
            token = None
            current_user = None
            # jwt is passed in the request header
            if "Authorization" in request.headers:
                token = request.headers["Authorization"].split("Bearer ")
                if len(token) < 2:
                    return {'message': 'Token is missing'}, 401
                token = token[1]
            # return 401 if token is not passed
            if not token:
                return {'message': 'Token is missing'}, 401
                # decoding the payload to fetch the stored details
            try:
                data = jwt.decode(
                    token, os.getenv("JWT_SECRET"),
                    algorithms=os.getenv("JWT_ALGO"),
                )
               
            except jwt.ExpiredSignatureError:
                data = jwt.decode(
                    token, os.getenv("JWT_SECRET"),
                    algorithms=os.getenv("JWT_ALGO"),
                    options={"verify_exp": False},
                )
                current_user = data["sub"]
                _ldap_connect(current_user, "")
                if group is not None and not ldap_in_group(group, current_user):
                    return error_response(
                        method="expired_token",
                        username="",
                        error=constants.UNAUTHORIZED,
                        status_code=401,
                    )
                return function(current_user, *args, **kwargs)
            except:
                return error_response(
                    method="expired_token",
                    username="",
                    error="Token is invalid",
                    status_code=401,
                )
            
            # Token is valid, can't be refreshed
            return error_response(
                    method="expired_token",
                    username="",
                    error="Token is still valid, can't be refreshed",
                    status_code=400,
                )
        wrapper.__name__ = function.__name__
        return wrapper
    return decorator


def decode_jwt(token):
    try:
        data = jwt.decode(
            token, os.getenv("JWT_SECRET"),
            algorithms=os.getenv("JWT_ALGO"),
        )
        current_user = data["sub"]
        _ldap_connect(current_user, "")

    except jwt.ExpiredSignatureError as e:

        return error_response(
            method="token_required",
            username="",
            error=str(e),
            status_code=401,
        )

    except:
        return error_response(
            method="token_required",
            username="",
            error="Token is invalid",
            status_code=401,
        )
    return current_user


DATABASE = "database.db"


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv
