# PlayerSaveResult

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**outcomes** | [**HashSet<models::PlayerSaveResultOutcome>**](PlayerSaveResultOutcome.md) | if the app is healthy | 
**previous_username** | Option<**String**> | the previous username involved in the result (only applies for the username_updated outcome) | [optional]
**other_unique_ids** | Option<**Vec<uuid::Uuid>**> | the other unique ids involved in the result (only applies for the other_unique_ids_present_for_username outcome) | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


