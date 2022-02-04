from settings import Settings
from libs.utils import (
    token_required
)
from services.tree import s_tree_base


def init(app):
    @app.route('/tree', methods=['GET', 'POST'])
    @app.route('/tree/<base>', methods=['GET', 'POST'])
    @token_required(Settings.ADMIN_GROUP)
    def tree_base(current_user, base=None):
        return s_tree_base(current_user, base)
