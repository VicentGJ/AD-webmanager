from ldap import *

connection = initialize("ldap://10.8.1.124:389")
connection.set_option(OPT_REFERRALS, 0)
connection.simple_bind_s("acvicentgj@cujae.edu.cu", "cujae2019*")
result_id = connection.search_s("dc=cujae,dc=edu,dc=cu", SCOPE_SUBTREE, "(sAMAccountName=administrator)", None)
print(result_id)