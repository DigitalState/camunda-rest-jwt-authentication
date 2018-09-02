#FROM digitalstate/camunda-bpm-platform:tomcat-7.9.0-json-logging
FROM camunda/camunda-bpm-platform:tomcat-7.9.0

RUN rm -r webapps/camunda-invoice

COPY docker/camunda/conf/bpm-platform.xml /camunda/conf/bpm-platform.xml

COPY docker/camunda/webapps/engine-rest/WEB-INF/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar /camunda/webapps/engine-rest/WEB-INF/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar
COPY docker/camunda/webapps/engine-rest/WEB-INF/web.xml /camunda/webapps/engine-rest/WEB-INF/web.xml

# Example usage of a standalone jar with the jwt validator class that is extended from the camunda-rest-api-jwt-authentication jar.
COPY docker/camunda/webapps/engine-rest/WEB-INF/lib/example-custom-jwt-validator-v1.0.jar /camunda/webapps/engine-rest/WEB-INF/lib/example-custom-jwt-validator-v1.0.jar
COPY docker/keys/key.pub /keys/key.pub