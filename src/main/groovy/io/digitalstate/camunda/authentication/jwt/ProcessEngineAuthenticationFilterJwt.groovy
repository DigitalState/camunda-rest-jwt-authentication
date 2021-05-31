package io.digitalstate.camunda.authentication.jwt

import groovy.transform.CompileStatic

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.camunda.bpm.BpmPlatform;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.ProcessEngines;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>
 * Servlet filter to plug in authentication.
 * </p>
 *
 * <p>Valid init-params:</p>
 * <table>
 * <thead>
 *   <tr><th>Parameter</th><th>Required</th><th>Expected value</th></tr>
 * <thead>
 * <tbody>
 *    <tr><td>{@value #AUTHENTICATION_PROVIDER_PARAM}</td><td>yes</td><td>An implementation of {@link AuthenticationProvider}</td></tr>
 *    <tr>
 *      <td>{@value #SERVLET_PATH_PREFIX}</td>
 *      <td>no</td>
 *      <td>The expected servlet path. Should only be set, if the underlying JAX-RS application is not deployed as a servlet (e.g. Resteasy allows deployments
 *      as a servlet filter). Value has to match what would be the {@link HttpServletRequest#getServletPath()} if it was deployed as a servlet.</td></tr>
 * </tbody>
 * </table>
 *
 * Has been modified from original source to remove group and tenant getters using Camunda DB, and expects the group and tenant IDs to be provided by the ValidatorJWT implementation.
 *
 * @author Thorben Lindhauer
 * @author Stephen Russett
 */

@CompileStatic
public class ProcessEngineAuthenticationFilterJwt implements Filter {

    // init params
    public static final String AUTHENTICATION_PROVIDER_PARAM = "authentication-provider";
    public static final String JWT_SECRET_PATH_PARAM = "jwt-secret-path";
    public static final String JWT_VALIDATOR_PARAM = "jwt-validator";
    public static final String EXCLUDED_URLS_PARAM = "excluded-urls";
    private static String jwtSecretPath
    private static String jwtValidator
    private static Class<?> jwtValidatorClass
    private static List<String> excludedUrls


    protected AuthenticationProviderJwt authenticationProvider;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String authenticationProviderClassName = filterConfig.getInitParameter(AUTHENTICATION_PROVIDER_PARAM);

        if (!jwtSecretPath){
            jwtSecretPath = filterConfig.getInitParameter(JWT_SECRET_PATH_PARAM)
        }

        if (!jwtValidator){
            jwtValidator = filterConfig.getInitParameter(JWT_VALIDATOR_PARAM)
        }

        if (!excludedUrls){
            String excludedList = filterConfig.getInitParameter(EXCLUDED_URLS_PARAM);
            if (excludedList != null) {
                excludedUrls = Arrays.asList(excludedList.split(","))
            }
        }

        if (authenticationProviderClassName == null) {
            throw new ServletException("Cannot instantiate authentication filter: no authentication provider set. init-param " + AUTHENTICATION_PROVIDER_PARAM + " missing");
        }

        try {
            Class<?> authenticationProviderClass = Class.forName(authenticationProviderClassName);
            authenticationProvider = (AuthenticationProviderJwt) authenticationProviderClass.newInstance();

        } catch (ClassNotFoundException e) {
            throw new ServletException("Cannot instantiate authentication filter: authentication provider not found", e);
        } catch (InstantiationException e) {
            throw new ServletException("Cannot instantiate authentication filter: cannot instantiate authentication provider", e);
        } catch (IllegalAccessException e) {
            throw new ServletException("Cannot instantiate authentication filter: constructor not accessible", e);
        } catch (ClassCastException e) {
            throw new ServletException("Cannot instantiate authentication filter: authentication provider does not implement interface " +
                    AuthenticationProviderJwt.class.getName(), e);
        }

        try{
            jwtValidatorClass = getClass().getClassLoader().loadClass(jwtValidator)
        } catch(all){
            // @TODO Add better Exception handling for JWT Validator class loading
            throw new ServletException("Could not load Jwt Validator Class: ${all.getLocalizedMessage()}")
        }

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String path = req.getRequestURI().substring(req.getContextPath().length());

        if (excludedUrls != null) {
            for (excludedPath in excludedUrls) {
                if (path.startsWith(excludedPath)) {
                    chain.doFilter(request, response);
                    return;
                }
            }
        }

        ProcessEngine engine = BpmPlatform.getDefaultProcessEngine();

        if (engine == null) {
            engine = ProcessEngines.getDefaultProcessEngine(false);
        }

        if (engine == null) {
            resp.setStatus(Status.NOT_FOUND.getStatusCode());
            String errMessage = "Default Process engine not available";
            ObjectMapper objectMapper = new ObjectMapper();

            resp.setContentType(MediaType.APPLICATION_JSON);
            objectMapper.writer().writeValue(resp.getWriter(), errMessage);
            resp.getWriter().flush();

            return;
        }

        AuthenticationResultJwt authenticationResult = authenticationProvider.extractAuthenticatedUser(req, engine, jwtValidatorClass, jwtSecretPath);

        if (authenticationResult.isAuthenticated()) {
            try {
                String authenticatedUser = authenticationResult.getAuthenticatedUser()

                // @TODO Review if null or empty array should be sent into Groups and Tenants when JWT does not have these claims
                List<String> groupIds = authenticationResult.getGroups() ?: []
                List<String> tenantIds = authenticationResult.getTenants() ?: []

                setAuthenticatedUser(engine, authenticatedUser, groupIds, tenantIds );

                chain.doFilter(request, response);

            } finally {
                clearAuthentication(engine);
            }
        } else {
            resp.setStatus(Status.UNAUTHORIZED.getStatusCode());
            authenticationProvider.augmentResponseByAuthenticationChallenge(resp, engine);
        }
    }

    @Override
    public void destroy() {
    }

    protected void setAuthenticatedUser(ProcessEngine engine, String userId, List<String> groupIds, List<String> tenantIds) {
        engine.getIdentityService().setAuthentication(userId, groupIds, tenantIds);
    }

    protected void clearAuthentication(ProcessEngine engine) {
        engine.getIdentityService().clearAuthentication();
    }

}