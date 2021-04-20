class Settings:
    SECRET_KEY = "AHDGIWIWBQSBKQYUQXBXKGAsdhahdflkjfgierqhs"
#    LDAP_DOMAIN = "your.domain"
#    SEARCH_DN = "dc=your,dc=search,dc=dn"
#    LDAP_SERVER = "your.ldap.server"
    DEBUG = True
    # URL_PREFIX = "/domain"
    TREE_BLACKLIST = [
        "CN=ForeignSecurityPrincipals", "OU=sudoers", "CN=Builtin",
        "CN=Infrastructure", "CN=LostAndFound", "CN=Managed Service Accounts",
        "CN=NTDS Quotas", "CN=Program Data", "CN=System",
        "OU=Domain Controllers"
    ]
    SICCIP_AWARE = False
    EXTRA_FIELDS = False
    ADMIN_GROUP = "Domain Admins"
    auth_admins = {}
    SEARCH_ATTRS = [('sAMAccountName', 'Usuario'), ('givenName', 'Nombre')]
    USER_ATTRIBUTES = [
        ["jpegPhoto", "Foto"],
        ["whenCreated", "Fecha de Creación", "time"],
        ["whenChanged", "Fecha de Modificación", "time"]
    ]
    TREE_ATTRIBUTES = [
        ['mail', "Email"], ['__type', "Tipo"], ['active', "Estado"]
    ]
#    TIMEZONE = "Your/Timezone"
