# QueryOptions

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**mode** | Option<**Mode**> |  (enum: contextual, non_contextual) | [optional][default to Contextual]
**flags** | Option<**Vec<Flags>**> |  (enum: resolve_inheritance, include_nodes_without_server_context, include_nodes_without_world_context, apply_inheritance_nodes_without_server_context, apply_inheritance_nodes_without_world_context) | [optional][default to ["resolve_inheritance","include_nodes_without_server_context","include_nodes_without_world_context","apply_inheritance_nodes_without_server_context","apply_inheritance_nodes_without_world_context"]]
**contexts** | Option<[**Vec<models::Context>**](Context.md)> | A set of context pairs. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


