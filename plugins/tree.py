import typing
from libs.common import iri_for as url_for
from settings import Settings
from flask import g, render_template, request, redirect, abort, jsonify
from libs.ldap_func import ldap_auth, ldap_get_entries, ldap_in_group


def init(app):
    @app.route('/tree', methods=['GET', 'POST'])
    @app.route('/tree/<base>', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def tree_base(base=None):

        if request.args.get('filters'):
            filter_array = request.args.get('filters').split(",")
        else:
            filter_array = None
        if not base:
            base = g.ldap['dn']
        elif not base.lower().endswith(g.ldap['dn'].lower()):
            base += ",%s" % g.ldap['dn']

        admin = ldap_in_group(Settings.ADMIN_GROUP)

        if not admin:
            abort(401)
        else:
            scope = "onelevel"         
            if filter_array:
                entries = get_entries("multiple_filters", filter_array, base, scope)
            else:
                entries = get_entries("top", "objectClass", base, scope)

            parent = None
            base_split = base.split(',')
            if not base_split[0].lower().startswith("dc"):
                parent = ",".join(base_split[1:])

            return jsonify(entries)

    def get_entries(filter_str, filter_attr, base, scope):
        """
        Get all entries that will be displayed in the tree
        """
        entries = []

        users = ldap_get_entries("objectClass=top", base, scope, ignore_erros=True)
        users = filter(
            lambda entry: 'displayName' in entry and 'sAMAccountName' in entry,
            users
        )
        if filter_str != "multiple_filters":
            users = filter(
                lambda entry: filter_attr in entry and filter_str in entry[filter_attr], 
                users
            )
            users: typing.List[typing.Dict] = sorted(
                users, key=lambda entry: entry['displayName']
            )

        if filter_str == "top":
            other_entries = ldap_get_entries("objectClass=top", base, scope, ignore_erros=True)
            other_entries = filter(lambda entry: 'displayName' not in entry, other_entries)
            other_entries = sorted(other_entries, key=lambda entry: entry['name'])
        else:
            other_entries = []
            
        for entry in users:
            if 'description' not in entry:
                if 'sAMAccountName' in entry:
                   entry['__description'] = entry['sAMAccountName']
            else:
                entry['__description'] = entry['description']

            entry['__target'] = url_for('tree_base', base=entry['distinguishedName'])

            entry['name'] = entry['displayName']
            entry['__type'] = "Usuario"
            # TODO: Fix this !!! we need photo support
            if 'jpegPhoto' in entry:
                entry.pop("jpegPhoto")

            if 'user' in entry['objectClass']:
                if entry['userAccountControl'] == 512:
                    entry['active'] = "Activo"
                else:
                    entry['active'] = "Desactivado"
            else:
                entry['active'] = "No disponible"

            if 'showInAdvancedViewOnly' in entry and entry['showInAdvancedViewOnly']:
                continue
            entries.append(entry)

        for entry in other_entries:
            if entry not in users:
                if 'description' not in entry:
                    if 'sAMAccountName' in entry:
                        entry['__description'] = entry['sAMAccountName']
                else:
                    entry['__description'] = entry['description']

                entry['__target'] = url_for('tree_base', base=entry['distinguishedName'])

                if 'group' in entry['objectClass']:
                    entry['__type'] = "Grupo"
                elif 'organizationalUnit' in entry['objectClass']:
                    entry['__type'] = "Unidad Organizativa"
                elif 'container' in entry['objectClass']:
                    entry['__type'] = "Contenedor"
                elif 'builtinDomain' in entry['objectClass']:
                    entry['__type'] = "Built-in"
                else:
                    entry['__type'] = "Desconocido"
                entries.append(entry)
                for blacklist in Settings.TREE_BLACKLIST:
                    if entry['distinguishedName'].startswith(blacklist):
                        entries.remove(entry)
        
        if filter_str == "multiple_filters":
            for filt in filter_attr:
                entries = apply_filter(filt, entries)

        return entries

    def apply_filter(filt, entries):
        """
        Apply a filter to a given list of users
        """

        new_filter = filt.split(":")
        if len(new_filter) > 1:
            attr = new_filter[0]
            value = str(new_filter[1]).replace('"', '').lower()
            entries = filter(
                lambda entry: attr in entry and
                value in str(entry[attr]).lower() if value != ""
                else value == str(entry[attr]).lower(),
                entries
            )

            entries: typing.List[typing.Dict] = sorted(
                entries,
                key=lambda entry: entry['displayName']
            )
            return entries
        else:
            abort(400)
