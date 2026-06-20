# \MessagingApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**messaging_custom_message**](MessagingApi.md#messaging_custom_message) | **POST** /messaging/custom | Send a custom message via the messaging service
[**messaging_push_update**](MessagingApi.md#messaging_push_update) | **POST** /messaging/update | Push an update via the messaging service
[**messaging_push_user_update**](MessagingApi.md#messaging_push_user_update) | **POST** /messaging/update/{uniqueId} | Push a user update via the messaging service



## messaging_custom_message

> messaging_custom_message(custom_message)
Send a custom message via the messaging service

Send a custom message via the messaging service.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**custom_message** | Option<[**CustomMessage**](CustomMessage.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## messaging_push_update

> messaging_push_update()
Push an update via the messaging service

Push an update via the messaging service.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## messaging_push_user_update

> messaging_push_user_update(unique_id)
Push a user update via the messaging service

Push a user update via the messaging service.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

