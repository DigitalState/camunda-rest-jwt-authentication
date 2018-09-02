FROM digitalstate/camunda-bpm-platform:tomcat-7.9.0-json-logging

RUN rm -r webapps/camunda-invoice

COPY docker/camunda/conf/bpm-platform.xml /camunda/conf/bpm-platform.xml
COPY docker/camunda/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar /camunda/lib/camunda-rest-api-jwt-authentication-v0.5-jar-with-dependencies.jar
COPY docker/camunda/webapps/engine-rest/WEB-INF/web.xml /camunda/webapps/engine-rest/WEB-INF/web.xml