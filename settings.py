class Settings:
    SECRET_KEY = "AHDGIWIWBQSBKQYUQXBXKGAsdhahdflkjfgierqhs"
#    LDAP_DOMAIN = "cujae.edu.cu"
#    SEARCH_DN = "dc=cujae,dc=edu,dc=cu"
#    LDAP_SERVER = "10.8.1.125"
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
    SEARCH_ATTRS = [('sAMAccountName', 'Username'), ('givenName', 'Name')]
    USER_ATTRIBUTES = [
        ["jpegPhoto", "Photo"],
    ]
    TREE_ATTRIBUTES = [
        ['mail', "Email"], ['__type', "Type"], ['active', "Status"]
    ]
#    TIMEZONE = "Your/Timezone"
