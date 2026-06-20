# \UsersApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**add_user_node**](UsersApi.md#add_user_node) | **POST** /user/{uniqueId}/nodes | Add a node to a user
[**add_user_nodes**](UsersApi.md#add_user_nodes) | **PATCH** /user/{uniqueId}/nodes | Add multiple nodes to a user
[**clear_user_nodes**](UsersApi.md#clear_user_nodes) | **DELETE** /user/{uniqueId}/nodes | Remove nodes from a user
[**create_user**](UsersApi.md#create_user) | **POST** /user | Create a new user
[**delete_user**](UsersApi.md#delete_user) | **DELETE** /user/{uniqueId} | Delete a user
[**get_user**](UsersApi.md#get_user) | **GET** /user/{uniqueId} | Get a users data
[**get_user_lookup**](UsersApi.md#get_user_lookup) | **GET** /user/lookup | Search for a user with the given username or unique id
[**get_user_meta**](UsersApi.md#get_user_meta) | **GET** /user/{uniqueId}/meta | Get a users metadata
[**get_user_nodes**](UsersApi.md#get_user_nodes) | **GET** /user/{uniqueId}/nodes | Get a users nodes (permissions data)
[**get_user_permission_check**](UsersApi.md#get_user_permission_check) | **GET** /user/{uniqueId}/permission-check | Run a permission check against a user
[**get_user_search**](UsersApi.md#get_user_search) | **GET** /user/search | Search for users with given nodes
[**get_users**](UsersApi.md#get_users) | **GET** /user | Get all existing users
[**patch_user**](UsersApi.md#patch_user) | **PATCH** /user/{uniqueId} | Update a users data
[**post_user_permission_check**](UsersApi.md#post_user_permission_check) | **POST** /user/{uniqueId}/permission-check | Run a permission check against a user with custom query options
[**set_user_nodes**](UsersApi.md#set_user_nodes) | **PUT** /user/{uniqueId}/nodes | Replace (set) a users nodes
[**user_demote**](UsersApi.md#user_demote) | **POST** /user/{uniqueId}/demote | Demote a user along a track
[**user_promote**](UsersApi.md#user_promote) | **POST** /user/{uniqueId}/promote | Promote a user along a track



## add_user_node

> Vec<models::Node> add_user_node(unique_id, temporary_node_merge_strategy, new_node)
Add a node to a user

Add a single node to the user

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**temporary_node_merge_strategy** | Option<[**TemporaryNodeMergeStrategy**](TemporaryNodeMergeStrategy.md)> | The node merge strategy |  |
**new_node** | Option<[**NewNode**](NewNode.md)> |  |  |

### Return type

[**Vec<models::Node>**](Node.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## add_user_nodes

> Vec<models::Node> add_user_nodes(unique_id, temporary_node_merge_strategy, new_node)
Add multiple nodes to a user

Add multiple nodes to the user

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**temporary_node_merge_strategy** | Option<[**TemporaryNodeMergeStrategy**](TemporaryNodeMergeStrategy.md)> | The node merge strategy |  |
**new_node** | Option<[**Vec<models::NewNode>**](NewNode.md)> |  |  |

### Return type

[**Vec<models::Node>**](Node.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## clear_user_nodes

> clear_user_nodes(unique_id, new_node)
Remove nodes from a user

Delete some or all of the nodes from a user.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**new_node** | Option<[**Vec<models::NewNode>**](NewNode.md)> | Specify the nodes to be deleted.  If the request body is empty, all nodes will be deleted. |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_user

> models::PlayerSaveResult create_user(new_user)
Create a new user

Create a new user.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**new_user** | Option<[**NewUser**](NewUser.md)> |  |  |

### Return type

[**models::PlayerSaveResult**](PlayerSaveResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_user

> delete_user(unique_id, player_data_only)
Delete a user

Delete a user

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**player_data_only** | Option<**bool**> | if only player data should be deleted |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user

> models::User get_user(unique_id)
Get a users data

Get a user by unique id (UUID).

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |

### Return type

[**models::User**](User.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user_lookup

> models::GetUserLookup200Response get_user_lookup(username, unique_id)
Search for a user with the given username or unique id

Lookup the unique id or username of a user with the given username or unique id.  You must specify one of the query parameters in the request.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**username** | Option<**String**> | The username to search for |  |
**unique_id** | Option<**uuid::Uuid**> | The unique id to search for |  |

### Return type

[**models::GetUserLookup200Response**](get_user_lookup_200_response.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user_meta

> models::Metadata get_user_meta(unique_id)
Get a users metadata

Get a users metadata

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |

### Return type

[**models::Metadata**](Metadata.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user_nodes

> Vec<models::Node> get_user_nodes(unique_id)
Get a users nodes (permissions data)

Get a users nodes.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |

### Return type

[**Vec<models::Node>**](Node.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user_permission_check

> models::PermissionCheckResult get_user_permission_check(unique_id, permission)
Run a permission check against a user

Run a permission check against a user

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**permission** | **String** | The permission to check for | [required] |

### Return type

[**models::PermissionCheckResult**](PermissionCheckResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_user_search

> Vec<models::UserSearchResult> get_user_search(key, key_starts_with, meta_key, r#type, group)
Search for users with given nodes

Search for users with given nodes.  You must specify one of the query parameters in the request.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key** | Option<**String**> | Search for nodes with a key equal to |  |
**key_starts_with** | Option<**String**> | Search for nodes with a key starting with |  |
**meta_key** | Option<**String**> | Search for meta nodes with a meta key equal to |  |
**r#type** | Option<**String**> | Search for nodes with a type equal to |  |
**group** | Option<**String**> | Search for inheritance nodes with the given group name |  |

### Return type

[**Vec<models::UserSearchResult>**](UserSearchResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_users

> Vec<uuid::Uuid> get_users()
Get all existing users

Returns an array of all known users.

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<uuid::Uuid>**](uuid::Uuid.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_user

> patch_user(unique_id, patch_user_request)
Update a users data

Update a user's data

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**patch_user_request** | Option<[**PatchUserRequest**](PatchUserRequest.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## post_user_permission_check

> models::PermissionCheckResult post_user_permission_check(unique_id, permission_check_request)
Run a permission check against a user with custom query options

Run a permission check against a user with custom query options

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**permission_check_request** | Option<[**PermissionCheckRequest**](PermissionCheckRequest.md)> |  |  |

### Return type

[**models::PermissionCheckResult**](PermissionCheckResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_user_nodes

> set_user_nodes(unique_id, new_node)
Replace (set) a users nodes

Override the users nodes

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**new_node** | Option<[**Vec<models::NewNode>**](NewNode.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## user_demote

> models::DemotionResult user_demote(unique_id, track_request)
Demote a user along a track

Demote a user along a track

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**track_request** | Option<[**TrackRequest**](TrackRequest.md)> |  |  |

### Return type

[**models::DemotionResult**](DemotionResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## user_promote

> models::PromotionResult user_promote(unique_id, track_request)
Promote a user along a track

Promote a user along a track

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unique_id** | **uuid::Uuid** | A player unique id (UUID) | [required] |
**track_request** | Option<[**TrackRequest**](TrackRequest.md)> |  |  |

### Return type

[**models::PromotionResult**](PromotionResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

