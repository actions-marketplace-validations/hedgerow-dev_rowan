import ldap


def find_user(conn, username):
    query = "(&(objectClass=person)(uid=" + username + "))"
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, query)
