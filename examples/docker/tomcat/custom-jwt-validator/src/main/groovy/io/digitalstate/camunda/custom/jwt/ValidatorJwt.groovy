package io.digitalstate.camunda.custom.jwt

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import io.digitalstate.camunda.authentication.jwt.AbstractValidatorJwt
import io.digitalstate.camunda.authentication.jwt.ValidatorResultJwt
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import groovy.transform.CompileStatic

@CompileStatic
public class ValidatorJwt extends AbstractValidatorJwt {

    private static final Logger LOG = LoggerFactory.getLogger(ValidatorJwt.class)
    private static String jwtSecret

    @Override
    ValidatorResultJwt validateJwt(String encodedCredentials, String jwtSecretPath) {
        if (!jwtSecret){
            try {
                jwtSecret = new FileInputStream(jwtSecretPath).getText()
            } catch(all){
                LOG.error("ERROR: Unable to load JWT Secret: ${all.getLocalizedMessage()}")
                return ValidatorResultJwt.setValidatorResult(false, null, null, null)
            }
        }

        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                .acceptNotBefore(new Date().getTime())
                .build();
            DecodedJWT jwt = verifier.verify(encodedCredentials)

                String username = jwt.getClaim('username').asString()
                List<String> groupIds = jwt.getClaim('groupIds').asList(String)
                List<String> tenantIds = jwt.getClaim('tenantIds').asList(String)

                if (!username){
                    LOG.error("BAD JWT: Missing username")
                    return ValidatorResultJwt.setValidatorResult(false, null, null, null)
                }

            return ValidatorResultJwt.setValidatorResult(true, username, groupIds, tenantIds)

        } catch(JWTVerificationException exception){
            LOG.error("BAD JWT: ${exception.getLocalizedMessage()}")
            return ValidatorResultJwt.setValidatorResult(false, null, null, null)
        }
    }

}
