# \TracksApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_track**](TracksApi.md#create_track) | **POST** /track | Create a new track
[**delete_track**](TracksApi.md#delete_track) | **DELETE** /track/{trackName} | Delete a track
[**get_track**](TracksApi.md#get_track) | **GET** /track/{trackName} | Get a tracks data
[**get_tracks**](TracksApi.md#get_tracks) | **GET** /track | Get all existing tracks
[**patch_track**](TracksApi.md#patch_track) | **PATCH** /track/{trackName} | Update a track



## create_track

> models::Track create_track(new_track)
Create a new track

Create a new track.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**new_track** | Option<[**NewTrack**](NewTrack.md)> |  |  |

### Return type

[**models::Track**](Track.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_track

> delete_track(track_name)
Delete a track

Delete a track

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**track_name** | **String** | A track name | [required] |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_track

> models::Track get_track(track_name)
Get a tracks data

Get a track

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**track_name** | **String** | A track name | [required] |

### Return type

[**models::Track**](Track.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_tracks

> Vec<String> get_tracks()
Get all existing tracks

Get all known tracks

### Parameters

This endpoint does not need any parameter.

### Return type

**Vec<String>**

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_track

> patch_track(track_name, patch_track_request)
Update a track

Update a track

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**track_name** | **String** | A track name | [required] |
**patch_track_request** | Option<[**PatchTrackRequest**](PatchTrackRequest.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

