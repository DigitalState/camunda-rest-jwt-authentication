package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic
import org.camunda.bpm.engine.ProcessEngine
import org.slf4j.Logger
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;

/**
 * <p>
 * Authenticates a request against the JWT Token and JWT Validator.  A successful validation will generate a ValidatorResultJwt object which is used to inject the username, group IDs, and tenant IDs into the engine's thread execution.
 * </p>
 *
 * @author Stephen Russett Github:StephenOTT
 */
@CompileStatic
public class AuthenticationFilterJwt implements AuthenticationProviderJwt {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationFilterJwt.class)
    protected static final String JWT_AUTH_HEADER_PREFIX = "Bearer ";

    @Override
    public AuthenticationResultJwt extractAuthenticatedUser(HttpServletRequest request,
                                                            ProcessEngine engine,
                                                            Class jwtValidatorClass,
                                                            String jwtSecretPath) {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(JWT_AUTH_HEADER_PREFIX)) {
            String encodedCredentials = authorizationHeader.substring(JWT_AUTH_HEADER_PREFIX.length())

            // Load the specific class defined in String jwtValidator variable.
            ValidatorResultJwt validatorResult
            try{
                AbstractValidatorJwt validator = (AbstractValidatorJwt)jwtValidatorClass.newInstance()
                validatorResult = validator.validateJwt(encodedCredentials, jwtSecretPath)
            } catch(all){
                // @TODO Add better Exception handling for JWT Validator class loading
                LOG.error("Could not load Jwt Validator Class: ${all.getLocalizedMessage()}")
                return AuthenticationResultJwt.unsuccessful()
            }

            if (validatorResult.getResult()){
                return AuthenticationResultJwt.successful(validatorResult.getAuthenticatedUsername(),
                        validatorResult.getGroupIds(),
                        validatorResult.getTenantIds())
            } else {
                return AuthenticationResultJwt.unsuccessful()
            }

        } else {
            LOG.error('JWT: missing JWT header')
            return AuthenticationResultJwt.unsuccessful();
        }
    }

    @Override
    public void augmentResponseByAuthenticationChallenge(
            HttpServletResponse response, ProcessEngine engine) {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, JWT_AUTH_HEADER_PREFIX + "realm=\"" + engine.getName() + "\"");
    }
}