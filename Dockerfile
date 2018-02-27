# TODO: Get image tag from Maven build?
FROM graylog/graylog:2.4.3-1
ARG JAR_FILE
COPY target/${JAR_FILE} /usr/share/graylog/plugin/
