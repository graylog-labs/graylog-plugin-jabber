package org.graylog2.alarmcallbacks.jabber.testcontainers;

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.joschi.jadconfig.util.Size;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.Wait;

import java.io.IOException;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

public class ProsodyContainer extends GenericContainer<ProsodyContainer> {
    public ProsodyContainer() {
        super("joschi/prosody-alpine:0.10.0-1");
    }

    @Override
    protected void configure() {
        this.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("Prosody")))
                .withClasspathResourceMapping("/prosody-conf", "/etc/prosody/conf.d", BindMode.READ_ONLY)
                .withClasspathResourceMapping("/ssl", "/etc/prosody/ssl", BindMode.READ_ONLY)
                .withCreateContainerCmdModifier((Consumer<CreateContainerCmd>) cmd -> cmd.withMemory(Size.megabytes(64L).toBytes()))
                .withExposedPorts(5222)
                .withNetworkAliases("prosody")
                .waitingFor(Wait.forListeningPort());
    }

    public void createUser(String username, String password, String domain) {
        final Container.ExecResult createUserResult;
        try {
            createUserResult = execInContainer("prosodyctl", "register", username, domain, password);
            assertThat(createUserResult.getStderr()).isEmpty();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
