from urllib import parse
import ldap
from flask import jsonify, request, flash, redirect, url_for, render_template
from libs.common import namefrom_dn
from libs.ldap_func import (ldap_auth, ldap_create_entry, ldap_delete_entry,
                            ldap_get_ou, ldap_ou_exists, ldap_update_attribute)
from settings import Settings
from flask_cors import cross_origin, CORS
from flask_wtf import FlaskForm
from wtforms.fields import StringField, TextAreaField
from wtforms.validators import DataRequired, Optional

class OU_form(FlaskForm):
    ou_name = StringField(label='OU name', validators=[DataRequired()])
    ou_description = TextAreaField(label='OU description', validators=[Optional()])


def init(app):
    @app.route('/ou/+add/<base>', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_add(base):
        title = "Add OU"
        form: FlaskForm = OU_form(request.form)
        
        field_mapping = [('description', form.ou_description)]
        
        form.visible_fields = [field[1] for field in field_mapping]
        form.visible_fields.insert(0, form.ou_name)

        if form.validate_on_submit():
            try:
                attributes = {
                    'objectClass': b"organizationalUnit",
                    }
                for attribute, field in field_mapping:
                    attributes[attribute] = field.data.encode('utf-8')

                ldap_create_entry("ou=%s,%s" % (form.ou_name.data, base), attributes)
                flash(u"OU created successfully.", "success")
 
                return redirect(url_for('tree_base', base=base))

            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")

        elif form.errors:
          flash(u"Data validation failed.", "error")

        return render_template("forms/basicform.html", form=form, title=title,
                               action="Add OU",
                               parent=url_for('tree_base'))
                               
    @app.route('/ou/<ou_name>/+delete', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_delete(ou_name):
        title = "Delete OU"

        if not ldap_ou_exists(ou_name=ou_name):
            flash(f"The OU: {namefrom_dn(ou_name)} doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        form = FlaskForm(request.form)

        if form.validate_on_submit():
            try:
                ou = ldap_get_ou(ou_name=ou_name)
                ldap_delete_entry(ou['distinguishedName'])
                flash(u"OU removed successfully.", "success")
                return redirect(url_for('tree_base'))
            except ldap.LDAPError as e:
                error = e.message['info'].split(":", 2)[-1].strip()
                error = str(error[0].upper() + error[1:])
                # error = (str(e).split("subtree_delete: ")[1]).replace("!'}", "").upper()
                flash(e, "error")
                
        elif form.errors:
                flash(u"Data validation failed.", "error")
        name = namefrom_dn(ou_name)
        return render_template("pages/ou_delete_es.html", title=title,
                               action="Delete OU", form=form,
                               ou_name=ou_name.upper(),
                               parent=url_for('tree_base', base=ou_name), name=name)

    @app.route('/ou/<ou_name>/+edit', methods=['GET', 'POST'])
    @ldap_auth(Settings.ADMIN_GROUP)
    def ou_edit(ou_name):
        title = "Edit OU"

        if not ldap_ou_exists(ou_name=ou_name):
            flash(f"The OU: {namefrom_dn(ou_name)} doesn't exists (err404)", "error")
            return redirect(url_for('tree_base'))

        ou = ldap_get_ou(ou_name)

        form = OU_form(request.form)
        field_mapping = [('distinguishedName',form.ou_name),('description', form.ou_description)]
        form.visible_fields = [field[1] for field in field_mapping]

        if form.validate_on_submit():
            try:
                for attribute, field in field_mapping:
                    value = field.data
                    if value != ou.get(attribute):
                        if attribute == 'distinguishedName':
                            dn: str = ou['distinguishedName'].split(",", 1)[1]
                            dn = "OU={0},{1}".format(value, dn)
                            ldap_update_attribute(ou['distinguishedName'],
                                                  "distinguishedName", "OU={0}".format(value))
                            ou['distinguishedName'] = dn
                        elif attribute:
                            ldap_update_attribute(ou['distinguishedName'],
                                                  attribute, value)

                flash(u"Successfully modified OU.", "success")
                return redirect(url_for('tree_base', base=ou['distinguishedName']))

            except ldap.LDAPError as e:
                e = dict(e.args[0])
                flash(e['info'], "error")

        elif form.errors:
            flash(u"Data verification failed.", "error")

        if not form.is_submitted():
            form.ou_name.data = namefrom_dn(ou.get('distinguishedName'))
            form.ou_description.data = ou.get('description')
            
        return render_template("forms/basicform.html", form=form, title=title,
                        action="Save Changes",
                        parent=url_for('tree_base'))
