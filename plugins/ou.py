import ldap
from flask import jsonify, request
from libs.common import namefrom_dn
from libs.ldap_func import (ldap_auth, ldap_create_entry, ldap_delete_entry,
                            ldap_get_ou, ldap_ou_exists, ldap_update_attribute)
from settings import Settings


def init(app):

    @app.route("/api/v1/ou/+add/", methods=["GET", "POST"])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_add():
        args = request.args
        base_found = False
        name_found = False
        res = {}
        mapping = []
        if "base" in args:
            base_found = True
            res['base'] = args['base']
        if 'name' in args:
            name_found = True
            res['name'] = args['name']
            mapping.append(('name',res["name"]))

        if not name_found or not base_found:
            res = {
                "ok": False,
                "error": {"message": "Error: name or base wasn't provided"},
            }
            return jsonify(res)
        
        if "description" in args:
            res['description'] = args['description']
            mapping.append(('description',res["description"]))

        try:
            attributes = {
                "objectClass": b"organizationalUnit",
            }
            for attribute, data in mapping:
                attributes[attribute] = data.encode("utf-8")
            ldap_create_entry("ou=%s,%s" % (res["name"], res["base"]), attributes)
            res['ok'] = True
        except ldap.LDAPError as e:
            e = dict(e.args[0])
            res=e

        return jsonify(res)

    @app.route("/api/v1/ou/+delete", methods=["GET", "POST"])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_delete():
        res = {}
        if 'dn' in request.args:
            res['dn'] = request.args['dn']
            res['name'] = namefrom_dn(res['dn'])
        else:
            res = {
                "ok": False,
                "error": {"message": "Error: dn wasn't provided"},
            }
            return jsonify(res)
        if not ldap_ou_exists(ou_name=res['dn']):
            res = {
                "ok": False,
                "error": {"message": "OU doesn't exists"}
            }
            return jsonify(res)

        try:
            ou = ldap_get_ou(ou_name=res['dn'])
            ldap_delete_entry(ou["distinguishedName"])
            res['message'] = "OU removed successfully"
            res['ok'] = True
            return jsonify(res)
        except ldap.LDAPError as e:
            error = e.message["info"].split(":", 2)[-1].strip()
            error = str(error[0].upper() + error[1:])
            res = {
                'error':{
                    'message':error
                }
            }
            return jsonify(res)

    @app.route("/api/v1/ou/+edit", methods=["GET", "POST"])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_edit():
        res = {}
        args = request.args
        if 'dn' in args:
            res['dn'] = args['dn']
            res['name'] = namefrom_dn(res['dn'])
        else:
            res = {
                "ok": False,
                "error": {"message": "Error: dn wasn't provided"},
            }
            return jsonify(res)
        if not ldap_ou_exists(ou_name=res['dn']):
            res = {
                "ok": False,
                "error": {"message": "OU doesn't exists"}
            }
            return jsonify(res)
        
        ou = ldap_get_ou(res["dn"])
        if 'name' in args:
            res['name'] = args['name']
            if not res["name"]:
                res = {
                    'error':{
                        'message': "OU name cant be blank"
                    },
                    'ok':False
                }
                return jsonify(res)
                
        res["description"] = ou['description']
        if "description" in args:
            res['description'] = args['description']


        mapping = [
            ("distinguishedName", res['name']),
            ("description", res['description']),
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

            res['ok'] = True
            return jsonify(res)

        except ldap.LDAPError as e:
            e = dict(e.args[0])
            return jsonify(e)