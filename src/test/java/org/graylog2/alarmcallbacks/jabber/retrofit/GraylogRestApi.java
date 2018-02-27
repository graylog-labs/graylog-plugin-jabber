package org.graylog2.alarmcallbacks.jabber.retrofit;

import com.fasterxml.jackson.databind.JsonNode;
import org.graylog2.rest.models.alarmcallbacks.requests.CreateAlarmCallbackRequest;
import org.graylog2.rest.models.alarmcallbacks.responses.AvailableAlarmCallbacksResponse;
import org.graylog2.rest.models.alarmcallbacks.responses.CreateAlarmCallbackResponse;
import org.graylog2.rest.models.system.plugins.responses.PluginList;
import org.graylog2.rest.resources.streams.responses.StreamListResponse;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.Headers;
import retrofit2.http.POST;
import retrofit2.http.Path;

public interface GraylogRestApi {
    @GET(".")
    Call<JsonNode> root();

    @GET("system/plugins")
    Call<PluginList> plugins();

    @GET("alerts/callbacks/types")
    Call<AvailableAlarmCallbacksResponse> alertCallbackTypes();

    @GET("streams/enabled")
    Call<StreamListResponse> enabledStreams();

    @POST("streams/{id}/alarmcallbacks")
    @Headers("Content-Type: application/json")
    Call<CreateAlarmCallbackResponse> createAlarmCallback(@Path("id") String streamId, @Body CreateAlarmCallbackRequest alarmCallback);

    @POST("alerts/callbacks/{id}/test")
    @Headers("Content-Type: application/json")
    Call<Void> triggerAlarmCallback(@Path("id") String alarmCallbackId);
}
