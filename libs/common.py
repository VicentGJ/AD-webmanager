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

import re
from flask import url_for, flash
from werkzeug.urls import uri_to_iri


class ReverseProxied(object):
    def __init__(self, app, prefix):
        self.app = app
        if prefix[0] != "/":
            self.prefix = "/%s" % prefix
        else:
            self.prefix = prefix

    def __call__(self, environ, start_response):
        script_name = self.prefix
        environ['SCRIPT_NAME'] = script_name
        path_info = environ['PATH_INFO']
        if path_info.startswith(script_name):
            environ['PATH_INFO'] = path_info[len(script_name):]

        return self.app(environ, start_response)


def iri_for(endpoint, **values):
    """
        Wrapper to url_for for utf-8 URLs.
    """
    return uri_to_iri(url_for(endpoint, **values))


def get_parsed_pager_attribute(pager):
    """
    Receive a codec pager attribute with the form
    I[F|R|L]numA_numB|E[F|R|L]numA|Dnum where
    I stands for Internet
    [F|L|R] translates to Full, Restricted or Local
    numA should be a float number representing the user quota
    numB should be a float number representing the percent of the quota available for social networks
    E stands for Email
    D its Dansguaridan

    For example a user with Full Internet access, 25.50 Units of quota for Internet, with Full email access and
    40 quota units for email and who's user should be filtered according with dansguardian group 2 will have a pager
    attribute like the following

    IF25.50|EF40.0|D2

    returns a dictionary with parsed data or None if errors are found
    """

    pager_parts = pager.split('|')
    if len(pager_parts) < 3:
        return None
    try:
        letter_type = pager_parts[0][1].capitalize()
        internet_type = letter_type if letter_type == 'F' or letter_type == 'R' else 'L'
        internet_quota = float(pager_parts[0][2:pager_parts[0].find('_')])
        socialnetwork_quota = float(pager_parts[0][pager_parts[0].find('_')+1:])
        letter_type = pager_parts[1][1].capitalize()
        email_type = letter_type if letter_type == 'F' or letter_type == 'R' else 'L'
        email_quota = float(pager_parts[1][2:])
        dansguardian_filter_number = int(pager_parts[2][1:])
        return {'internet_type': internet_type, 'internet_quota': internet_quota,
                'socialnetwork_quota': socialnetwork_quota, 'email_type': email_type,
                'email_quota': email_quota, 'dansguardian_filter': dansguardian_filter_number}
    except ValueError:
        return None

def namefrom_dn(dn):
    return dn.split('=')[1].split(',')[0]
    
def get_objclass(dn):
    return dn.split('=')[0]

def password_is_valid(password):
    """
    Verify the strength of 'password'
    Returns a dict with 
    error-keys: length_errors, digit_errors, lowercase_errors, uppercase_errors, symbol_errors;
    values: True or False, being True on a key if there was an error found

    there is password_ok key that is True if all the other keys are False

    A password is considered valid if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 7

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # # searching for symbols 
    # The \W metacharacter is used to find a non-word character. 
    # A word character is a character from a-z, A-Z, 0-9, including the _    
    symbol_error = (re.search(r"\W", password) is None) and (password.count('_') == 0)

    # overall result
    password_ok = not ( length_error or digit_error  or symbol_error )
    if password_ok:
        return None
    else:
        return {
            'length_error' : length_error,
            'digit_error' : digit_error,
            'symbol_error' : symbol_error,
        }

def flash_password_errors(password_validation):
    """
    Flashes all error messages from the password validation
    
    Args:
        password_validation (dict): dict returned from password_is_valid()
    """
    for error_key, password_error in password_validation.items():
        if password_error:
            if error_key == 'length_error':
                flash("Password must have at least 8 characters", "error")
            if error_key == 'digit_error':
                flash("Password must have at least a digit","error")
            if error_key == 'uppercase_error':
                flash("Password must have at least an upercase letter","error")
            if error_key == 'lowercase_error':
                flash("Password must have at least a lowercase letter","error")
            if error_key == 'symbol_error':
                flash("Password must have at least a symbol","error")

def get_encoded_list(given_list : list):
    encoded_list = []
    if len(given_list):
        for i in given_list:
            encoded_list.append(i.encode('utf-8'))
    else:
        encoded_list = [b'0']
    return encoded_list

def get_decoded_list(given_list : list):
    decoded_list = []
    if len(given_list):
        for i in given_list:
            decoded_list.append(i.decode('utf-8'))
    else:
        decoded_list = ['0']
    return decoded_list