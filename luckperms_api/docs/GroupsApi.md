# \GroupsApi

All URIs are relative to *http://..*

Method | HTTP request | Description
------------- | ------------- | -------------
[**add_group_node**](GroupsApi.md#add_group_node) | **POST** /group/{groupName}/nodes | Add a node to a group
[**add_group_nodes**](GroupsApi.md#add_group_nodes) | **PATCH** /group/{groupName}/nodes | Add multiple Group Nodes
[**clear_group_nodes**](GroupsApi.md#clear_group_nodes) | **DELETE** /group/{groupName}/nodes | Remove nodes from a group
[**create_group**](GroupsApi.md#create_group) | **POST** /group | Create a new group
[**delete_group**](GroupsApi.md#delete_group) | **DELETE** /group/{groupName} | Delete a group
[**get_group**](GroupsApi.md#get_group) | **GET** /group/{groupName} | Get a groups data
[**get_group_meta**](GroupsApi.md#get_group_meta) | **GET** /group/{groupName}/meta | Get a groups metadata
[**get_group_nodes**](GroupsApi.md#get_group_nodes) | **GET** /group/{groupName}/nodes | Get a groups nodes (permissions data)
[**get_group_permission_check**](GroupsApi.md#get_group_permission_check) | **GET** /group/{groupName}/permission-check | Run a permission check against a group
[**get_group_search**](GroupsApi.md#get_group_search) | **GET** /group/search | Search for groups with given nodes
[**get_groups**](GroupsApi.md#get_groups) | **GET** /group | Get all existing groups
[**post_group_permission_check**](GroupsApi.md#post_group_permission_check) | **POST** /group/{groupName}/permission-check | Run a permission check against a group with custom query options
[**set_group_nodes**](GroupsApi.md#set_group_nodes) | **PUT** /group/{groupName}/nodes | Replace (set) a groups nodes



## add_group_node

> Vec<models::Node> add_group_node(group_name, temporary_node_merge_strategy, new_node)
Add a node to a group

Add a single node to the group

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
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


## add_group_nodes

> Vec<models::Node> add_group_nodes(group_name, temporary_node_merge_strategy, new_node)
Add multiple Group Nodes

Add multiple nodes to the group

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
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


## clear_group_nodes

> clear_group_nodes(group_name, new_node)
Remove nodes from a group

Delete some or all of the nodes from a group.  If the request body is empty, all nodes will be deleted.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
**new_node** | Option<[**Vec<models::NewNode>**](NewNode.md)> | Specify the nodes to be deleted.  If the request body is empty, all nodes will be deleted. |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_group

> models::Group create_group(new_group)
Create a new group

Create a new group.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**new_group** | Option<[**NewGroup**](NewGroup.md)> |  |  |

### Return type

[**models::Group**](Group.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_group

> delete_group(group_name)
Delete a group

Delete a group

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_group

> models::Group get_group(group_name)
Get a groups data

Get a group

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |

### Return type

[**models::Group**](Group.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_group_meta

> models::Metadata get_group_meta(group_name)
Get a groups metadata

Get the groups metadata

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |

### Return type

[**models::Metadata**](Metadata.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_group_nodes

> Vec<models::Node> get_group_nodes(group_name)
Get a groups nodes (permissions data)

Get a groups nodes.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |

### Return type

[**Vec<models::Node>**](Node.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_group_permission_check

> models::PermissionCheckResult get_group_permission_check(group_name, permission)
Run a permission check against a group

Run a permission check against a group

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
**permission** | **String** | The permission to check for | [required] |

### Return type

[**models::PermissionCheckResult**](PermissionCheckResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_group_search

> Vec<models::GroupSearchResult> get_group_search(key, key_starts_with, meta_key, r#type, group)
Search for groups with given nodes

Search for groups with given nodes.  You must specify one of the query parameters in the request.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key** | Option<**String**> | Search for nodes with a key equal to |  |
**key_starts_with** | Option<**String**> | Search for nodes with a key starting with |  |
**meta_key** | Option<**String**> | Search for meta nodes with a meta key equal to |  |
**r#type** | Option<**String**> | Search for nodes with a type equal to |  |
**group** | Option<**String**> | Search for inheritance nodes with the given group name |  |

### Return type

[**Vec<models::GroupSearchResult>**](GroupSearchResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_groups

> Vec<String> get_groups()
Get all existing groups

Get all known groups

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


## post_group_permission_check

> models::PermissionCheckResult post_group_permission_check(group_name, permission_check_request)
Run a permission check against a group with custom query options

Run a permission check against a group with custom query options

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
**permission_check_request** | Option<[**PermissionCheckRequest**](PermissionCheckRequest.md)> |  |  |

### Return type

[**models::PermissionCheckResult**](PermissionCheckResult.md)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_group_nodes

> set_group_nodes(group_name, new_node)
Replace (set) a groups nodes

Override the groups nodes

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**group_name** | **String** | A group name | [required] |
**new_node** | Option<[**Vec<models::NewNode>**](NewNode.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[apikey](../README.md#apikey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

