from libs.common import iri_for as url_for
from settings import Settings
from flask import abort, flash, g, render_template, redirect, request
from flask_wtf import FlaskForm
from flask.json import jsonify
from libs.ldap_func import ldap_auth, ldap_create_entry, ldap_delete_entry, \
    ldap_get_entry_simple, ldap_get_members, ldap_get_membership, \
    ldap_get_group, ldap_in_group, ldap_rename_entry, ldap_update_attribute, ldap_group_exists, \
    LDAP_AD_GROUPTYPE_VALUES, ldap_add_users_to_group

import ldap
import struct
from libs.logs import logs
from libs.utils import (
    token_required
)
from utils import constants
from services.group import (
    s_group_add, s_group_overview, s_group_delete, s_group_edit,
    s_group_delmember, s_group_addmembers
)


def init(app):
    @app.route('/group/+add', methods=['POST'])
    @token_required(Settings.ADMIN_GROUP)
    def group_add(current_user):
        return s_group_add(current_user)

    @app.route('/group/<groupname>', methods=['GET'])
    @token_required("Domain Users")
    def group_overview(current_user, groupname):
        return s_group_overview(current_user, groupname)

    @app.route('/group/<groupname>/+delete', methods=['GET', 'POST'])
    @token_required(Settings.ADMIN_GROUP)
    def group_delete(current_user, groupname):
        return s_group_delete(current_user, groupname)

    @app.route('/group/<groupname>/+edit', methods=['GET', 'POST'])
    @token_required(Settings.ADMIN_GROUP)
    def group_edit(current_user, groupname):
        return s_group_edit(current_user, groupname)

    @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    @token_required(Settings.ADMIN_GROUP)
    def group_addmembers(current_user, groupname):
        return s_group_addmembers(current_user, groupname)

    @app.route('/group/<groupname>/+del-member/<member>',
               methods=['GET', 'POST'])
    @token_required(Settings.ADMIN_GROUP)
    def group_delmember(current_user, groupname, member):
        return s_group_delmember(current_user, groupname, member)