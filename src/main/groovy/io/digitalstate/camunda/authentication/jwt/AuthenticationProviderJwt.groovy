
package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic
import org.camunda.bpm.engine.ProcessEngine;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A provider to handle the authentication of {@link HttpServletRequest}s.
 * May implement a specific authentication scheme.
 * Has been modified from the original source, to support JWT authentication
 *
 * @author Thorben Lindhauer
 * @author Stpehen Russett
 */
@CompileStatic
public interface AuthenticationProviderJwt {

    /**
     * Checks the request for authentication. May not return null, but always an {@link AuthenticationResultJwt} that indicates, whether
     * authentication was successful, and, if true, always provides the authenticated user, and optionally group IDs and tenant IDs.
     *
     * @param request the request to authenticate
     * @param engine the process engine the request addresses.
     * @param jwtValidator the fully qualified class name that extends AbstractValidatorJwt, that will be used to validate the JWT.
     * @param jwtSecretPath the file path of the location of the secret used to decode/validate the JWT.  May be null if secret is pulled from another location.
     */
    AuthenticationResultJwt extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine, Class jwtValidator, String jwtSecretPath);

    /**
     * <p>
     * Callback to add an authentication challenge to the response to the client. Called in case of unsuccessful authentication.
     * </p>
     *
     * <p>
     * For example, a Http Basic auth implementation may set the WWW-Authenticate header to <code>Basic realm="engine name"</code>.
     * </p>
     *
     * @param request the response to augment
     * @param engine the process engine the request addressed. May be considered as an authentication realm to create a specific authentication
     * challenge
     */
    void augmentResponseByAuthenticationChallenge(HttpServletResponse response, ProcessEngine engine);
}
