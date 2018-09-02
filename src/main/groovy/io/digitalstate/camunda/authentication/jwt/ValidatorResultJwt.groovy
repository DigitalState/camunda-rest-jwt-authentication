package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic

@CompileStatic
public class ValidatorResultJwt {
    Boolean result
    String authenticatedUsername
    List<String> groupIds
    List<String> tenantIds

    public ValidatorResultJwt(Boolean result, String authenticatedUsername, List<String> groupIds, List<String> tenantIds){
        this.result = result
        this.authenticatedUsername = authenticatedUsername
        this.groupIds = groupIds
        this.tenantIds = tenantIds
    }

    public static ValidatorResultJwt setValidatorResult( Boolean result, String authenticatedUsername, List<String> groupIds, List<String> tenantIds){
        return new ValidatorResultJwt(result, authenticatedUsername, groupIds, tenantIds)
    }

    public Boolean getResult(){
        return this.result
    }
    public String getAuthenticatedUsername(){
        return this.authenticatedUsername
    }
    public List<String> getGroupIds(){
        return this.groupIds
    }
    public List<String> getTenantIds(){
        return this.tenantIds
    }
}
