package com.orca.auth;

import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

/**
 * ldap/active directory connector for enterprise authentication auditing.
 * scans for weak configs, stale accounts, and privilege escalation paths.
 */
public class LdapConnector {

    private final String host;
    private final int port;
    private final String baseDn;
    private DirContext context;

    public LdapConnector(String host, int port, String baseDn) {
        this.host = host;
        this.port = port;
        this.baseDn = baseDn;
    }

    public boolean connect(String bindDn, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, String.format("ldap://%s:%d", host, port));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        try {
            context = new InitialDirContext(env);
            return true;
        } catch (NamingException e) {
            return false;
        }
    }

    public List<Map<String, String>> searchUsers(String filter) {
        List<Map<String, String>> users = new ArrayList<>();
        if (context == null) return users;
        try {
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                "uid", "cn", "mail", "memberOf", "lastLogon", "pwdLastSet"
            });
            NamingEnumeration<SearchResult> results =
                context.search(baseDn, filter, controls);
            while (results.hasMore()) {
                SearchResult result = results.next();
                Attributes attrs = result.getAttributes();
                Map<String, String> user = new HashMap<>();
                user.put("dn", result.getNameInNamespace());
                NamingEnumeration<? extends Attribute> attrEnum = attrs.getAll();
                while (attrEnum.hasMore()) {
                    Attribute attr = attrEnum.next();
                    user.put(attr.getID(), attr.get().toString());
                }
                users.add(user);
            }
        } catch (NamingException e) {
            // connection or search error
        }
        return users;
    }

    public List<Map<String, String>> findStaleAccounts(int daysSinceLogin) {
        long threshold = System.currentTimeMillis() - (long) daysSinceLogin * 86400000L;
        String filter = String.format(
            "(&(objectClass=user)(lastLogon<=%d))", threshold
        );
        return searchUsers(filter);
    }

    public List<Map<String, String>> findPrivilegedUsers() {
        return searchUsers("(&(objectClass=user)(memberOf=cn=Domain Admins,*))");
    }

    public List<String> auditPasswordPolicy() {
        List<String> findings = new ArrayList<>();
        if (context == null) {
            findings.add("not connected to ldap server");
            return findings;
        }
        try {
            Attributes attrs = context.getAttributes(baseDn, new String[]{
                "minPwdLength", "pwdHistoryLength", "lockoutThreshold",
                "maxPwdAge", "minPwdAge"
            });
            Attribute minLen = attrs.get("minPwdLength");
            if (minLen != null) {
                int len = Integer.parseInt(minLen.get().toString());
                if (len < 12) {
                    findings.add("weak: minimum password length is " + len + " (recommend 12+)");
                }
            }
            Attribute lockout = attrs.get("lockoutThreshold");
            if (lockout != null) {
                int threshold = Integer.parseInt(lockout.get().toString());
                if (threshold == 0) {
                    findings.add("critical: account lockout is disabled");
                } else if (threshold > 10) {
                    findings.add("weak: lockout threshold is " + threshold + " (recommend 5)");
                }
            }
        } catch (NamingException e) {
            findings.add("error reading password policy: " + e.getMessage());
        }
        return findings;
    }

    public void disconnect() {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException e) {
                // ignore close errors
            }
            context = null;
        }
    }

    public static void main(String[] args) {
        LdapConnector connector = new LdapConnector("ldap.example.com", 389, "dc=example,dc=com");
        System.out.println("ldap connector initialized: " + connector.host);
    }
}
