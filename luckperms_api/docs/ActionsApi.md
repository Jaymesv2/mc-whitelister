# \ActionsApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_actions**](ActionsApi.md#get_actions) | **GET** /action | Query actions
[**submit_action**](ActionsApi.md#submit_action) | **POST** /action | Submit a new action



## get_actions

> models::GetActions200Response get_actions(page_size, page_number, source, user, group, track, search)
Query actions

Query actions from the action logger.  If pageSize or pageNumber are specified, both must be specified. If neither are specified, no pagination will be used and all results will be returned. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**page_size** | Option<**i32**> | The number of actions to return on each page |  |
**page_number** | Option<**i32**> | The page to return |  |
**source** | Option<**String**> | Filter by source user unique id |  |
**user** | Option<**String**> | Filter by target user unique id |  |
**group** | Option<**String**> | Filter by target group name |  |
**track** | Option<**String**> | Filter by target track name |  |
**search** | Option<**String**> | Filter by search value in source name, target name or description. |  |

### Return type

[**models::GetActions200Response**](get_actions_200_response.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## submit_action

> submit_action(action)
Submit a new action

Submit a new action to the action logger.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**action** | Option<[**Action**](Action.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

