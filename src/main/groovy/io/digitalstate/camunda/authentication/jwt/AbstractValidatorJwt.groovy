package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic

@CompileStatic
abstract class AbstractValidatorJwt {
// @TODO Add use of logger

    abstract ValidatorResultJwt validateJwt(String encodedCredentials, String jwtSecretPath)

}
