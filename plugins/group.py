from settings import Settings
from libs.utils import token_required
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