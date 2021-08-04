from libs.common import iri_for as url_for
from settings import Settings
from flask import abort, flash, g, render_template, redirect, request
from flask_wtf import FlaskForm
from wtforms import RadioField, TextAreaField, TextField, HiddenField
from wtforms.validators import DataRequired
from flask.json import jsonify
from libs.ldap_func import ldap_auth, ldap_create_entry, ldap_delete_entry, \
    ldap_get_entry_simple, ldap_get_members, ldap_get_membership, \
    ldap_get_group, ldap_in_group, ldap_update_attribute, ldap_group_exists, \
    LDAP_AD_GROUPTYPE_VALUES, ldap_add_users_to_group

import ldap
import struct


def init(app):
    @app.route('/group/+add', methods=['POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_add():

        try:
            data: dict = request.json
            base = data["base"]
            data.pop("base")
            #data.pop("group_flags") ## si se va a usar esta bandera, descomentar
            attributes = {'objectClass': b"group"}

            for attribute, field in data.items():
                if attribute == "groupType":
                    group_type = int(data["group_type"].data) + int(data["group_flags"].data)
                    attributes[attribute] = str(struct.unpack("i",
                                                                  struct.pack("I", int(group_type)))[0]).encode('utf-8')
                elif attribute and field:
                    attributes[attribute] = field.encode('utf-8')
            
            attributes.pop("group_flags")
            attributes.pop("group_type")
            ldap_create_entry("CN=%s,%s" % (data["sAMAccountName"], base), attributes)

            return jsonify({"response": ("CN=%s,%s" % (data["sAMAccountName"], base), attributes)})
        except ldap.LDAPError as e:
            return jsonify({"response": str(e)})
        except KeyError as e:
            return jsonify({"response": "Missing key {0}".format(str(e))})



    @app.route('/group/<groupname>')
    @ldap_auth("Domain Users")
    def group_overview(groupname):
        title = "Detalles del Grupo - %s" % groupname

        if not ldap_group_exists(groupname=groupname):
            abort(404)

        identity_fields = [('sAMAccountName', "Nombre"),
                           ('description', u"Descripción")]

        group_fields = [('sAMAccountName', "Nombre"),
                        ('description', u"Descripción")]

        group = ldap_get_group(groupname=groupname)

        admin = ldap_in_group(Settings.ADMIN_GROUP) and not group['groupType'] & 1

        group_details = [ldap_get_group(entry, 'distinguishedName')
                         for entry in ldap_get_membership(groupname)]

        group_details = list(filter(None, group_details))
        groups = sorted(group_details, key=lambda entry: entry['sAMAccountName'])

        member_list = []
        for entry in ldap_get_members(groupname):
            member = ldap_get_entry_simple({'distinguishedName': entry})
            if 'sAMAccountName' not in member:
                continue
            member_list.append(member)

        members = sorted(member_list, key=lambda entry:
                         entry['sAMAccountName'])

        parent = ",".join(group['distinguishedName'].split(',')[1:])

        return jsonify({"group": group, 
                        "identity_fields": identity_fields, 
                        "group_fields" :group_fields, 
                        "admin":admin, 
                        "groups": groups, 
                        "members":members, 
                        "parent":parent,
                        "grouptype_values": LDAP_AD_GROUPTYPE_VALUES})
        
    @app.route('/group/<groupname>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_delete(groupname):
        title = "Eliminar grupo"

        if not ldap_group_exists(groupname):
            abort(404)

        # form = FlaskForm(request.form)

        # if form.validate_on_submit():
        try:
            group = ldap_get_group(groupname=groupname)
            ldap_delete_entry(group['distinguishedName'])
            return jsonify({"response": "success"})
        except ldap.LDAPError as e:
            error = e.message['info'].split(":", 2)[-1].strip()
            error = str(error[0].upper() + error[1:])
            return jsonify({"response": str(error)})
        

    @app.route('/group/<groupname>/+edit', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_edit(groupname):
        title = "Editar grupo"

        if not ldap_group_exists(groupname):
            abort(404)

        group = ldap_get_group(groupname)

        # We can't edit system groups
        if group['groupType'] & 1:
            abort(401)

        # form = GroupEdit(request.form)
        # field_mapping = [('sAMAccountName', form.name),
        #                  ('description', form.description),
        #                  (None, form.group_type),
        #                  ('groupType', form.group_flags)]

        # form.visible_fields = [field[1] for field in field_mapping]

        # form.group_flags.choices = [(key, value[0]) for key, value in
        #                             LDAP_AD_GROUPTYPE_VALUES.items()
        #                             if value[1]]

        # if form.validate_on_submit():
        data: dict = request.json
        try:
            for attribute, field in data.items():
                value = field
                if value != group.get(attribute):
                    if attribute == 'sAMAccountName':
                        # Rename the account
                        ldap_update_attribute(group['distinguishedName'],
                                              "sAMAccountName", value)
                        # Finish by renaming the whole record
                        ldap_update_attribute(group['distinguishedName'],
                                              "cn", value)
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
            return jsonify({"response": "success"})
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify({"response": str(e)})
        

    @app.route('/group/<groupname>/+add-members', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_addmembers(groupname):
        title = "Adicionar miembros"

        if not ldap_group_exists(groupname):
            abort(404)

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
                error = u"Nombre de usuario inválido: %s" % member
                return jsonify({"response": str(error)})
            entries.add(entry['distinguishedName'])
        else:
            try:
                ldap_add_users_to_group(group['distinguishedName'],
                                      "member", list(entries))
                return jsonify({"response": "success"})
            except ldap.LDAPError as e:
                e = dict(e.args[0])
                return jsonify({"response": str(e)})

    @app.route('/group/<groupname>/+del-member/<member>',
               methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def group_delmember(groupname, member):
        title = "Quitar del grupo"

        group = ldap_get_group(groupname)
        if not group or 'member' not in group:
            abort(404)

        member = ldap_get_entry_simple({'sAMAccountName': member})
        if not member:
            abort(404)

        if not member['distinguishedName'] in group['member']:
            abort(404)

        #form = GroupDelMember(request.form)

        
        try:
            members = group['member']
            members.remove(member['distinguishedName'])
            ldap_update_attribute(group['distinguishedName'],"member", members)
            return jsonify({"response": "success"})
            
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify({"response": e})