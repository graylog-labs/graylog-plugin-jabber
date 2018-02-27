package org.graylog2.alarmcallbacks.jabber.testcontainers;

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.joschi.jadconfig.util.Size;
import okhttp3.HttpUrl;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.Wait;

import java.time.Duration;
import java.util.function.Consumer;

public class GraylogContainer extends GenericContainer<GraylogContainer> {
    private static final int GRAYLOG_HTTP_PORT = 9000;

    public GraylogContainer(String tag) {
        this("graylog-plugin-jabber", tag);
    }

    public GraylogContainer(String image, String tag) {
        super(image + ":" + tag);
    }

    @Override
    protected void configure() {
        this.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("Graylog")))
                .withCreateContainerCmdModifier((Consumer<CreateContainerCmd>) cmd -> cmd.withMemory(Size.gigabytes(1L).toBytes()))
                .withEnv("GRAYLOG_PASSWORD_SECRET", "supersecretpasswordpepper")
                .withEnv("GRAYLOG_ROOT_USERNAME", "admin")
                .withEnv("GRAYLOG_ROOT_PASSWORD_SHA2", "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918")
                .withEnv("GRAYLOG_WEB_ENDPOINT_URI", "http://127.0.0.1:9000/api")
                .withEnv("GRAYLOG_MESSAGE_JOURNAL_ENABLED", "false")
                .withEnv("GRAYLOG_DEFAULT_MESSAGE_OUTPUT_CLASS", "org.graylog2.outputs.DiscardMessageOutput")
                .withExposedPorts(GRAYLOG_HTTP_PORT)
                .withNetworkAliases("graylog")
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(5L)));
    }

    public HttpUrl getGraylogUrl() {
        return new HttpUrl.Builder()
                .scheme("http")
                .username("admin")
                .password("admin")
                .host(this.getContainerIpAddress())
                .port(this.getMappedPort(GRAYLOG_HTTP_PORT))
                .encodedPath("/api/")
                .build();
    }
}
