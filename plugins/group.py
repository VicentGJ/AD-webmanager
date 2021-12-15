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
    decode_ldap_error, error_response, simple_success_response
)
from utils import constants



def init(app):
    @app.route('/group/+add', methods=['POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs([])
    def group_add():

        try:
            data: dict = request.json
            base = data["base"]
            data.pop("base")
            #data.pop("group_flags") ## si se va a usar esta bandera, descomentar
            attributes = {'objectClass': b"group"}

            for attribute, field in data.items():
                if attribute == "groupType":
                    group_type = int(data["group_type"].data) + int(
                        data["group_flags"].data
                    )
                    attributes[attribute] = str(
                        struct.unpack("i", struct.pack(
                            "I", int(group_type))
                        )[0]
                    ).encode('utf-8')
                elif attribute and field:
                    attributes[attribute] = field.encode('utf-8')

            attributes.pop("group_flags")
            attributes.pop("group_type")
            ldap_create_entry(
                "CN=%s,%s" % (data["sAMAccountName"], base), attributes
            )
            return simple_success_response(
                ("CN=%s,%s" % (data["sAMAccountName"], base), attributes)
            )
        except ldap.LDAPError as e:
            error = decode_ldap_error(e)
            response = error_response(
                method="group_add",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response
        except KeyError as e:
            error = "Missing key {0}".format(str(e))
            response = error_response(
                method="user_add",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

    @app.route('/group/<groupname>')
    @ldap_auth("Domain Users")
    @logs(['groupname'])
    def group_overview(groupname):
        title = "Detalles del Grupo - %s" % groupname

        if not ldap_group_exists(groupname=groupname):
            error = "Group not found"
            response = error_response(
                method="group_overview",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        identity_fields = [('sAMAccountName', "Nombre"),
                           ('description', u"Descripción")]

        group_fields = [('sAMAccountName', "Nombre"),
                        ('description', u"Descripción")]

        group = ldap_get_group(groupname=groupname)

        admin = ldap_in_group(Settings.ADMIN_GROUP) and \
            not group['groupType'] & 1

        group_details = [ldap_get_group(entry, 'distinguishedName')
                         for entry in ldap_get_membership(groupname)]

        group_details = list(filter(None, group_details))
        groups = sorted(
            group_details,
            key=lambda entry: entry['sAMAccountName']
        )

        member_list = []
        for entry in ldap_get_members(groupname):
            member = ldap_get_entry_simple({'distinguishedName': entry})
            if 'sAMAccountName' not in member:
                continue
            member_list.append(member)

        members = sorted(member_list, key=lambda entry:
                         entry['sAMAccountName'])

        parent = ",".join(group['distinguishedName'].split(',')[1:])

        return simple_success_response({
            "group": group,
            "identity_fields": identity_fields,
            "group_fields": group_fields,
            "admin": admin,
            "groups": groups,
            "members": members,
            "parent": parent,
            "grouptype_values": LDAP_AD_GROUPTYPE_VALUES
        })

    @app.route('/group/<groupname>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs(['groupname'])
    def group_delete(groupname):
        title = "Eliminar grupo"

        if not ldap_group_exists(groupname):
            error = "Group not found"
            response = error_response(
                method="group_delete",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response
        try:
            group = ldap_get_group(groupname=groupname)
            ldap_delete_entry(group['distinguishedName'])
            return simple_success_response("Success")

        except ldap.LDAPError as e:
            # TODO TO CHECK
            error = e.message['info'].split(":", 2)[-1].strip()
            error = str(error[0].upper() + error[1:])
            response = error_response(
                method="user_add",
                username=request.authorization.username,
                error=error,
                status_code=500,
            )
            return response

    @app.route('/group/<groupname>/+edit', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs(['groupname'])
    def group_edit(groupname):
        title = "Editar grupo"

        if not ldap_group_exists(groupname):
            error = "Group not found"
            response = error_response(
                method="group_edit",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        group = ldap_get_group(groupname)

        # We can't edit system groups
        if group['groupType'] & 1:
            response = error_response(
                method="group_edit",
                username=request.authorization.username,
                error=constants.UNAUTHORIZED,
                status_code=401,
            )
            return response

        data: dict = request.json
        try:
            for attribute, field in data.items():
                value = field
                if value != group.get(attribute):
                    if attribute == 'cn':
                        ldap_rename_entry(
                            group['distinguishedName'],
                            'cn',
                            value
                        )
                        group = ldap_get_group(value, 'cn')
                    elif attribute == 'sAMAccountName':
                        ldap_update_attribute(
                            group['distinguishedName'],
                            "sAMAccountName",
                            value
                        )
                        group = ldap_get_group(value)
                    elif attribute == "groupType":
                        group_type = int(data["group_type"].data) + \
                            int(data["group_flags"].data)
                        ldap_update_attribute(
                            group['distinguishedName'], attribute,
                            str(
                                struct.unpack(
                                    "i", struct.pack(
                                        "I", int(group_type)))[0]))
                    elif attribute:
                        ldap_update_attribute(group['distinguishedName'],
                                              attribute, value)
            return simple_success_response("Success")
        except ldap.LDAPError as e:
            # TODO TO CHECK
            e = dict(e.args[0])
            return {"data": None, "error": str(e)}, 500

    @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs(['groupname'])
    def group_addmembers(groupname):
        title = "Adicionar miembros"

        if not ldap_group_exists(groupname):
            error = "Group not found"
            response = error_response(
                method="group_addmembers",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response


        ##data["members"] -> List
        data: dict = request.json

        group = ldap_get_group(groupname)
        if 'member' in group:
            entries = set(group['member'])
        else:
            entries = set()
        for member in data["members"]:
            print(member)
            entry = ldap_get_entry_simple({"sAMAccountName": member})
            if not entry:
                error = u"Username invalid: %s" % member
                response = error_response(
                    method="group_addmembers",
                    username=request.authorization.username,
                    error=error,
                    status_code=400,
                )
                return response
            entries.add(entry['distinguishedName'])
        else:
            try:
                ldap_add_users_to_group(
                    group['distinguishedName'],
                    "member",
                    list(entries)
                )
                return jsonify({"response": "success"})
            except ldap.LDAPError as e:
                # TODO TO CHECK
                e = dict(e.args[0])
                return {"data": None, "error": str(e)}, 500

    @app.route('/group/<groupname>/+del-member/<member>',
               methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    @logs(['groupname', 'member'])
    def group_delmember(groupname, member):
        title = "Quitar del grupo"

        group = ldap_get_group(groupname)
        if not group or 'member' not in group:
            error = "Group not found or member attribute not in group"
            response = error_response(
                method="group_delmember",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        member = ldap_get_entry_simple({'sAMAccountName': member})
        if not member:
            error = "Member not found"
            response = error_response(
                method="group_delmember",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        if not member['distinguishedName'] in group['member']:
            error = "Member not in group"
            response = error_response(
                method="group_delmember",
                username=request.authorization.username,
                error=error,
                status_code=404,
            )
            return response

        try:
            members = group['member']
            members.remove(member['distinguishedName'])
            ldap_update_attribute(
                group['distinguishedName'],
                "member",
                members
            )
            return simple_success_response("Success")

        except ldap.LDAPError as e:
            # TODO TO CHECK
            e = dict(e.args[0])
            return {"data": None, "error": str(e)}, 500
