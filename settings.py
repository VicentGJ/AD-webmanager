class Settings:
    SECRET_KEY = "AHDGIWIWBQSBKQYUQXBXKGAsdhahdflkjfgierqhs"
    LDAP_DOMAIN = "cujae.edu.cu"
    SEARCH_DN = "dc=cujae,dc=edu,dc=cu"
    LDAP_SERVER = "10.8.1.125"
    DEBUG = True
    # URL_PREFIX = "/domain"
    TREE_BLACKLIST = ["CN=ForeignSecurityPrincipals", "OU=sudoers", "CN=Builtin", "CN=Infrastructure",
                      "CN=LostAndFound", "CN=Managed Service Accounts", "CN=NTDS Quotas", "CN=Program Data",
                      "CN=System", "OU=Domain Controllers"]
    SICCIP_AWARE = False
    
    #Data format for auto-generate form fields:
    # ['label','ldadField','dataType']
    # if dataType is 'select'
    # ['label','ldadField','dataType',[('choice1LDAP', "choice1Label"), ('ChoiceNLDAP', "ChoiceNLabel")]]]

    # example:
    # extra_fields = [
    #     ['Usuario Manual','cUJAEPersonExternal', 'boolean'],
    #     ['Tipo de Persona','cUJAEPersonType', 'select',[('Worker', "Trabajador"), ('Student', "Estudiante")]],
    #     ['Carné Identidad','cUJAEPersonDNI', 'string']
    # ]
    extra_fields = []
    EXTRA_FIELDS = True

    EXTRA_FIELDS = True
    ADMIN_GROUP = "SM Admins"
    SEARCH_ATTRS = [('sAMAccountName', 'Usuario'), ('givenName', 'Nombre')]
