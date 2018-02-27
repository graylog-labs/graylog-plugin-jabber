package org.graylog2.alarmcallbacks.jabber;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import org.graylog2.alarmcallbacks.jabber.retrofit.GraylogRestApi;
import org.graylog2.alarmcallbacks.jabber.smack.IncomingListener;
import org.graylog2.alarmcallbacks.jabber.testcontainers.GraylogContainer;
import org.graylog2.alarmcallbacks.jabber.testcontainers.MongoDBContainer;
import org.graylog2.alarmcallbacks.jabber.testcontainers.ProsodyContainer;
import org.graylog2.rest.models.alarmcallbacks.requests.CreateAlarmCallbackRequest;
import org.graylog2.rest.models.alarmcallbacks.responses.AvailableAlarmCallbackSummaryResponse;
import org.graylog2.rest.models.alarmcallbacks.responses.AvailableAlarmCallbacksResponse;
import org.graylog2.rest.models.alarmcallbacks.responses.CreateAlarmCallbackResponse;
import org.graylog2.rest.models.system.plugins.responses.PluginList;
import org.graylog2.rest.resources.streams.responses.StreamListResponse;
import org.graylog2.shared.bindings.providers.ObjectMapperProvider;
import org.jivesoftware.smack.chat2.ChatManager;
import org.jivesoftware.smack.tcp.XMPPTCPConnection;
import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.testcontainers.containers.Network;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Strings.isNullOrEmpty;
import static com.jayway.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assume.assumeFalse;

public class GraylogIntegrationTest {
    @ClassRule
    public static Network NETWORK = Network.newNetwork();

    private static final String GIT_SHA = System.getProperty("git.sha");
    private static final ProsodyContainer PROSODY = new ProsodyContainer().withNetwork(NETWORK);
    private static final MongoDBContainer MONGODB = new MongoDBContainer().withNetwork(NETWORK);
    private static final GraylogContainer GRAYLOG = new GraylogContainer(GIT_SHA).withNetwork(NETWORK);

    @ClassRule
    public static final RuleChain CHAIN = RuleChain.outerRule(NETWORK)
            .around(PROSODY)
            .around(MONGODB)
            .around(GRAYLOG);

    @BeforeClass
    public static void initialize() throws InterruptedException {
        assumeFalse(isNullOrEmpty(GIT_SHA));

        PROSODY.createUser("user1", "test1234", "example.org");
        PROSODY.createUser("user2", "test1234", "example.org");
    }

    private final GraylogRestApi graylogService;

    public GraylogIntegrationTest() {
        final OkHttpClient okHttpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .authenticator((route, response) -> {
                    if (response.request().header("Authorization") != null) {
                        return null; // Give up, we've already attempted to authenticate.
                    }

                    String credential = Credentials.basic("admin", "admin");
                    return response.request().newBuilder()
                            .header("Authorization", credential)
                            .build();
                })
                .build();
        final ObjectMapper objectMapper = new ObjectMapperProvider().get();
        final Retrofit retrofit = new Retrofit.Builder()
                .client(okHttpClient)
                .addConverterFactory(JacksonConverterFactory.create(objectMapper))
                .baseUrl(GRAYLOG.getGraylogUrl())
                .build();
        this.graylogService = retrofit.create(GraylogRestApi.class);
    }

    @Test
    public void canary() throws IOException {
        final Response<JsonNode> response = graylogService.root().execute();
        assertThat(response.isSuccessful()).isTrue();
        final JsonNode body = response.body();
        assertThat(body).isNotNull();
        assertThat(body.path("tagline").isTextual()).isTrue();
    }

    @Test
    public void pluginHasBeenLoaded() throws IOException {
        final Response<PluginList> response = graylogService.plugins().execute();
        assertThat(response.isSuccessful()).isTrue();

        final PluginList responseBody = response.body();
        assertThat(responseBody).isNotNull();
        assertThat(responseBody.total()).isPositive();
        assertThat(responseBody.plugins())
                .filteredOn(metaData -> "org.graylog2.alarmcallbacks.jabber.JabberAlarmCallback".equals(metaData.uniqueId()))
                .isNotEmpty();
    }

    @Test
    public void jabberAlarmCallbackIsAvailable() throws IOException {
        final Response<AvailableAlarmCallbacksResponse> response = graylogService.alertCallbackTypes().execute();
        assertThat(response.isSuccessful()).isTrue();

        final AvailableAlarmCallbacksResponse responseBody = response.body();
        assertThat(responseBody).isNotNull();
        assertThat(responseBody.types).containsKey("org.graylog2.alarmcallbacks.jabber.JabberAlarmCallback");

        final AvailableAlarmCallbackSummaryResponse summaryResponse = responseBody.types.get("org.graylog2.alarmcallbacks.jabber.JabberAlarmCallback");
        assertThat(summaryResponse.name).isEqualTo("Jabber Alarm Callback");
    }

    @Test
    public void createAndTriggerAlarmCallback() throws Exception {
        final String prosodyHost = PROSODY.getContainerIpAddress();
        final int prosodyPort = PROSODY.getMappedPort(5222);
        final CreateAlarmCallbackRequest alarmCallbackRequest = CreateAlarmCallbackRequest.create(
                "org.graylog2.alarmcallbacks.jabber.JabberAlarmCallback",
                "Jabber Callback",
                ImmutableMap.<String, Object>builder()
                        .put("hostname", "prosody")
                        .put("port", 5222)
                        .put("username", "user1")
                        .put("password", "test1234")
                        .put("service_name", "example.org")
                        .put("recipient", "user2@example.org")
                        .build()
        );

        final XMPPTCPConnection xmppConnection = createXMPPConnection(prosodyHost, prosodyPort, "user2", "example.org", "test1234");
        try {
            xmppConnection.connect().login();
            final IncomingListener listener = new IncomingListener();
            final ChatManager chatManager = ChatManager.getInstanceFor(xmppConnection);
            chatManager.addIncomingListener(listener);

            final String streamId = getDefaultStreamId();
            final String alarmCallbackId = createAlarmCallback(streamId, alarmCallbackRequest);

            final Response<Void> triggerResponse = graylogService.triggerAlarmCallback(alarmCallbackId).execute();
            assertThat(triggerResponse.isSuccessful()).isTrue();

            await().until(() -> !listener.messages.isEmpty());

            assertThat(listener.messages).containsKey("user1@" + "example.org");
            assertThat(listener.messages.get("user1@" + "example.org").getBody())
                    .startsWith("Graylog alert for stream <All messages>\n")
                    .containsSequence(
                            "Stream ID: " + streamId,
                            "Date: ",
                            "Trigger: Test Alert (dummy)",
                            "Triggered condition: ")
                    .endsWith("No message backlog available.");
        } finally {
            xmppConnection.instantShutdown();
        }
    }

    private XMPPTCPConnection createXMPPConnection(String host, int port, String username, String domain, String password) throws Exception {
        final XMPPTCPConnectionConfiguration.Builder config = XMPPTCPConnectionConfiguration.builder()
                .setUsernameAndPassword(username, password)
                .setXmppDomain(domain)
                .setHost(host)
                .setPort(port);

        return new XMPPTCPConnection(config.build());
    }

    private String getDefaultStreamId() throws IOException {
        final Response<StreamListResponse> response = graylogService.enabledStreams().execute();
        assertThat(response.isSuccessful()).isTrue();
        final StreamListResponse responseBody = response.body();
        assertThat(responseBody).isNotNull();
        return responseBody.streams()
                .stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Expected default stream"))
                .id();

    }

    private String createAlarmCallback(String streamId, CreateAlarmCallbackRequest request) throws IOException {
        final Response<CreateAlarmCallbackResponse> response = graylogService.createAlarmCallback(streamId, request).execute();
        assertThat(response.isSuccessful()).isTrue();
        final CreateAlarmCallbackResponse responseBody = response.body();
        assertThat(responseBody).isNotNull();
        return responseBody.alarmCallbackId();
    }
}
