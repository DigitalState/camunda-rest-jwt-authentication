package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic

@CompileStatic
public class AuthenticationResultJwt {

    protected boolean isAuthenticated;

    protected String authenticatedUser;
    protected List<String> groups;
    protected List<String> tenants;

    public AuthenticationResultJwt(String authenticatedUser, boolean isAuthenticated, List<String> groups, List<String> tenants) {
        this.authenticatedUser = authenticatedUser;
        this.isAuthenticated = isAuthenticated;
        this.groups = groups
        this.tenants = tenants
    }

    public String getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(String authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    public void setAuthenticated(boolean isAuthenticated) {
        this.isAuthenticated = isAuthenticated;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }

    public List<String> getTenants() {
        return tenants;
    }

    public void setTenants(List<String> tenants) {
        this.tenants = tenants;
    }

    public static AuthenticationResultJwt successful(String userId, List<String> groups = null, List<String> tenants = null) {
        return new AuthenticationResultJwt(userId, true, groups, tenants);
    }

    public static AuthenticationResultJwt unsuccessful() {
        return new AuthenticationResultJwt(null, false, null, null);
    }

    public static AuthenticationResultJwt unsuccessful(String userId) {
        return new AuthenticationResultJwt(userId, false, null, null);
    }
}