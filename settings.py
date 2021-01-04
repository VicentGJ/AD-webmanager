class Settings:
    SECRET_KEY = "AHDGIWIWBQSBKQYUQXBXKGAsdhahdflkjfgierqhs"
    LDAP_DOMAIN = "cujae.edu.cu"
    SEARCH_DN = "dc=cujae,dc=edu,dc=cu"
    LDAP_SERVER = "10.8.1.63"
    DEBUG = True
    # URL_PREFIX = "/domain"
    SICCIP_AWARE = False
    EXTRA_FIELDS = True
    ADMIN_GROUP = "SM Admins"
    SEARCH_ATTRS = [('cUJAEPersonDNI', 'Carné ID'), ('sAMAccountName', 'Usuario'), ('givenName', 'Nombre')]
