from urllib import parse
import ldap
from flask import jsonify, request
from libs.common import namefrom_dn
from libs.ldap_func import (ldap_auth, ldap_create_entry, ldap_delete_entry,
                            ldap_get_ou, ldap_ou_exists, ldap_update_attribute)
from settings import Settings
from flask_cors import cross_origin, CORS
def init(app):
    cors = CORS(app)
    @app.route("/api/v1/ou/+add/", methods=["GET", "POST"])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_add():
        response = {}
        args = request.args
        base_found = False
        name_found = False

        mapping = []
        if "base" in args:
            base_found = True
            response['base'] = args['base']
        if 'name' in args:
            name_found = True
            response['name'] = args['name']
            mapping.append(('name',response["name"]))

        if not name_found or not base_found:
            response = {
                "ok": False,
                "error": {"message": "Error: name or base wasn't provided"},
            }
            return jsonify(response)
        
        if "description" in args:
            response['description'] = args['description']
            mapping.append(('description',response["description"]))

        try:
            attributes = {
                "objectClass": b"organizationalUnit",
            }
            for attribute, data in mapping:
                attributes[attribute] = data.encode("utf-8")
            ldap_create_entry("ou=%s,%s" % (response["name"], response["base"]), attributes)
            response['ok'] = True
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            response=e

        return jsonify(response)

    @app.route("/api/v1/ou/+delete/", methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_delete():
        response = {}
        if 'dn' in request.args:
            response['dn'] = request.args['dn']
            response['name'] = namefrom_dn(response['dn'])
        else:
            response = {
                "ok": False,
                "error": {"message": "Error: dn wasn't provided"},
            }
            return jsonify(response)
        if not ldap_ou_exists(ou_name=response['dn']):
            response = {
                "ok": False,
                "error": {"message": "OU doesn't exists"}
            }
            return jsonify(response)

        try:
            ou = ldap_get_ou(ou_name=response['dn'])
            ldap_delete_entry(ou["distinguishedName"])
            response['ok'] = True
            return jsonify(response)
        except ldap.LDAPError as e:
            error = e.message["info"].split(":", 2)[-1].strip()
            error = str(error[0].upper() + error[1:])
            response = {
                'error':{
                    'message':error
                }
            }
            return jsonify(response)

    @app.route("/api/v1/ou/+edit/", methods=["GET", "POST"])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_edit():
        response = {}
        args = request.args
        if 'dn' in args:
            response['dn'] = args['dn']
            response['name'] = namefrom_dn(response['dn'])
        else:
            response = {
                "ok": False,
                "error": {"message": "Error: dn wasn't provided"},
            }
            return jsonify(response)
        if not ldap_ou_exists(ou_name=response['dn']):
            response = {
                "ok": False,
                "error": {"message": "OU doesn't exists"}
            }
            return jsonify(response)
        
        ou = ldap_get_ou(response["dn"])
        if 'name' in args:
            response['name'] = args['name']
            if not response["name"]:
                response = {
                    'error':{
                        'message': "OU name cant be blank"
                    },
                    'ok':False
                }
                return jsonify(response)

        response["description"] = ou['description']
        if "description" in args:
            response['description'] = args['description']

        mapping = [
            ("distinguishedName", response['name']),
            ("description", response['description']),
        ]

        try:
            for attribute, data in mapping:
                if data != ou.get(attribute):
                    if attribute == "distinguishedName":
                        dn: str = ou["distinguishedName"].split(",", 1)[1]
                        dn = "OU={0},{1}".format(data, dn)
                        ldap_update_attribute(
                            ou["distinguishedName"],
                            "distinguishedName",
                            "OU={0}".format(data),
                        )
                        ou["distinguishedName"] = dn
                    elif attribute:
                        ldap_update_attribute(
                            ou["distinguishedName"], attribute, data
                        )

            response['ok'] = True
            return jsonify(response)

        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify(e)