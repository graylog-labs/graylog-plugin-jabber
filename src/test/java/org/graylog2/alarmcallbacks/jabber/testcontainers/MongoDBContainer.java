package org.graylog2.alarmcallbacks.jabber.testcontainers;

import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.joschi.jadconfig.util.Size;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;

import java.util.function.Consumer;

public class MongoDBContainer extends GenericContainer<MongoDBContainer> {
    public MongoDBContainer() {
        super("mongo:3");
    }

    @Override
    protected void configure() {
        this.withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("MongoDB")))
                .withCreateContainerCmdModifier((Consumer<CreateContainerCmd>) cmd -> cmd.withMemory(Size.megabytes(128L).toBytes()))
                .withNetworkAliases("mongo");
    }
}
