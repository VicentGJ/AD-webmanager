from decouple import config

class Settings:
    SECRET_KEY = config("SECRET_KEY")
    LDAP_DOMAIN = config("LDAP_DOMAIN")
    SEARCH_DN = config("SEARCH_DN")
    LDAP_DN = config("LDAP_DN", "DC=%s" % ",DC=".join(LDAP_DOMAIN.split(".")))
    LDAP_SERVER = config("LDAP_SERVER")
    DEBUG = config("DEBUG")
    USE_LOGGING = config("USE_LOGGING")
    SICCIP_AWARE = config("SICCIP_AWARE")
#    EXTRA_FIELDS = config("EXTRA_FIELDS") # Not used
    ADMIN_GROUP = config("ADMIN_GROUP")

    TREE_BLACKLIST = [
        "CN=ForeignSecurityPrincipals", "OU=sudoers", "CN=Builtin",
        "CN=Infrastructure", "CN=LostAndFound", "CN=Managed Service Accounts",
        "CN=NTDS Quotas", "CN=Program Data", "CN=System",
        "OU=Domain Controllers", "CN=Guest", "CN=krbtgt"
    ]
    SEARCH_ATTRS = [('sAMAccountName', 'Username'), ('givenName', 'Name')]
    USER_ATTRIBUTES = [
        ["jpegPhoto", "Photo"],
    ]
    TREE_ATTRIBUTES = [
        ['mail', "Email"], ['__type', "Type"], ['active', "Status"]
    ]
    TIMEZONE = "Your/Timezone"