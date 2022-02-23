from settings import Settings
from libs.ldap_func import ldap_auth
from libs.utils import token_required, expired_token
from services.user import (
    s_get_jwt, s_refresh_token, s_user_overview, s_user_add, s_user_changepw,
    s_user_delete, s_user_edit_profile,
)
from flask import request


def init(app):

    @app.route('/user/login', methods=['GET'])
    @ldap_auth("Domain Users")
    def login_jwt():
        return s_get_jwt()

    @app.route('/user/refresh-token', methods=['POST'])
    @expired_token("Domain Users")
    def refresh_token(current_user):
        data: dict = request.json
        return s_refresh_token(current_user, data)


    @app.route('/user/+add', methods=['POST'])
    @token_required(Settings.ADMIN_GROUP)
    def user_add(current_user):
        return s_user_add(current_user)


    @app.route('/user/<value>', methods=['GET'])
    @token_required("Domain Users")
    def user_overview(current_user, value):
        return s_user_overview(current_user, value)

    @app.route('/user/<username>/+changepw', methods=['POST'])
    @token_required("Domain Users")
    def user_changepw(current_user, username):
        return s_user_changepw(current_user, username)

    @app.route('/user/<username>', methods=['DELETE'])
    @token_required(Settings.ADMIN_GROUP)
    def user_delete(current_user, username):
        return s_user_delete(current_user, username)

    @app.route('/user/<username>', methods=['PUT'])
    @token_required(Settings.ADMIN_GROUP)
    def user_edit_profile(current_user, username):
        return s_user_edit_profile(current_user, username)
