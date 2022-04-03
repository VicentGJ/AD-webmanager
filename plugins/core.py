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

from flask import g, redirect, session
from libs.common import iri_for as url_for
from libs.ldap_func import ldap_auth, ldap_get_entry_simple


def init(app):
    @app.route('/')
    @app.route('/user')
    @ldap_auth("Domain Users")
    def core_index():
        return redirect(url_for('user_overview', username=g.ldap['username']))

    @app.route('/+logout')
    @ldap_auth("Domain Users")
    def core_logout():
        session['logout'] = 1
        return redirect(url_for('core_index'))
