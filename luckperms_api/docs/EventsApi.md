# \EventsApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_event_custom_message_receive**](EventsApi.md#get_event_custom_message_receive) | **GET** /event/custom-message-receive | Subscribe to the CustomMessageReceiveEvent
[**get_event_log_broadcast**](EventsApi.md#get_event_log_broadcast) | **GET** /event/log-broadcast | Subscribe to the LogBroadcastEvent
[**get_event_post_network_sync**](EventsApi.md#get_event_post_network_sync) | **GET** /event/post-network-sync | Subscribe to the PostNetworkSyncEvent
[**get_event_post_sync**](EventsApi.md#get_event_post_sync) | **GET** /event/post-sync | Subscribe to the PostSyncEvent
[**get_event_pre_network_sync**](EventsApi.md#get_event_pre_network_sync) | **GET** /event/pre-network-sync | Subscribe to the PreNetworkSyncEvent
[**get_event_pre_sync**](EventsApi.md#get_event_pre_sync) | **GET** /event/pre-sync | Subscribe to the PreSyncEvent



## get_event_custom_message_receive

> Vec<models::GetEventCustomMessageReceive200ResponseInner> get_event_custom_message_receive()
Subscribe to the CustomMessageReceiveEvent

Subscribes to the CustomMessageReceiveEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventCustomMessageReceive200ResponseInner>**](get_event_custom_message_receive_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_event_log_broadcast

> Vec<models::GetEventLogBroadcast200ResponseInner> get_event_log_broadcast()
Subscribe to the LogBroadcastEvent

Subscribes to the LogBroadcastEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventLogBroadcast200ResponseInner>**](get_event_log_broadcast_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_event_post_network_sync

> Vec<models::GetEventPostNetworkSync200ResponseInner> get_event_post_network_sync()
Subscribe to the PostNetworkSyncEvent

Subscribes to the PostNetworkSyncEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventPostNetworkSync200ResponseInner>**](get_event_post_network_sync_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_event_post_sync

> Vec<models::GetEventPostSync200ResponseInner> get_event_post_sync()
Subscribe to the PostSyncEvent

Subscribes to the PostSyncEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventPostSync200ResponseInner>**](get_event_post_sync_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_event_pre_network_sync

> Vec<models::GetEventPreNetworkSync200ResponseInner> get_event_pre_network_sync()
Subscribe to the PreNetworkSyncEvent

Subscribes to the PreNetworkSyncEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventPreNetworkSync200ResponseInner>**](get_event_pre_network_sync_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_event_pre_sync

> Vec<models::GetEventPreSync200ResponseInner> get_event_pre_sync()
Subscribe to the PreSyncEvent

Subscribes to the PreSyncEvent using [Server-Sent Events (SSE)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<models::GetEventPreSync200ResponseInner>**](get_event_pre_sync_200_response_inner.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/event-stream

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

