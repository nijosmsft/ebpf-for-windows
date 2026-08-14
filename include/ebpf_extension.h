// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_result.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"

#define EBPF_MAP_OPERATION_HELPER                                                                                      \
    0x01                               /* Called by a BPF program. When this flag is not set, the provider function is \
                                        * called in the context of the original user mode process, so the provider may \
                                        * implicitly use the current process's handle table (e.g., to resolve file     \
                                        * descriptors passed as map values). */
#define EBPF_MAP_OPERATION_UPDATE 0x02 /* Update operation. */
#define EBPF_MAP_OPERATION_MAP_CLEANUP 0x04 /* Map cleanup operation. */

typedef ebpf_result_t (*_ebpf_extension_dispatch_function)();

typedef uint64_t epoch_state_t[4];

typedef struct _ebpf_extension_dispatch_table
{
    uint16_t version; ///< Version of the dispatch table.
    uint16_t count;   ///< Number of entries in the dispatch table.
    _Field_size_(count) _ebpf_extension_dispatch_function function[1];
} ebpf_extension_dispatch_table_t;

/**
 * @brief Invoke the eBPF program.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was
 * created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY The operation failed due to lack of memory.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD The required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_invoke_function_t)(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result);

/**
 * @brief Prepare the eBPF program for batch invocation.
 *
 * @param[in] state_size The size of the state to be allocated, which should be greater than or equal to
 * sizeof(ebpf_execution_context_state_t).
 * @param[out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY The operation failed due to lack of memory.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD The required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_batch_begin_invoke_function_t)(
    size_t state_size, _Out_writes_(state_size) void* state);

/**
 * @brief Invoke the eBPF program in batch mode.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was
 * created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 * @param[in] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
typedef ebpf_result_t (*ebpf_program_batch_invoke_function_t)(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state);

/**
 * @brief Clean up the eBPF program after batch invocation.
 *
 * @param[in,out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 */
typedef ebpf_result_t (*ebpf_program_batch_end_invoke_function_t)(_Inout_ void* state);

typedef enum _ebpf_link_dispatch_table_version
{
    EBPF_LINK_DISPATCH_TABLE_VERSION_1 = 1, ///< Initial version of the dispatch table.
    EBPF_LINK_DISPATCH_TABLE_VERSION_CURRENT =
        EBPF_LINK_DISPATCH_TABLE_VERSION_1, ///< Current version of the dispatch table.
} ebpf_link_dispatch_table_version_t;

#define EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_1 4
#define EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_CURRENT \
    EBPF_LINK_DISPATCH_TABLE_FUNCTION_COUNT_1 ///< Current number of functions in the dispatch table.

typedef struct _ebpf_extension_program_dispatch_table
{
    uint16_t version; ///< Version of the dispatch table.
    uint16_t count;   ///< Number of entries in the dispatch table.
    ebpf_program_invoke_function_t ebpf_program_invoke_function;
    ebpf_program_batch_begin_invoke_function_t ebpf_program_batch_begin_invoke_function;
    ebpf_program_batch_invoke_function_t ebpf_program_batch_invoke_function;
    ebpf_program_batch_end_invoke_function_t ebpf_program_batch_end_invoke_function;
} ebpf_extension_program_dispatch_table_t;

typedef struct _ebpf_extension_data
{
    ebpf_extension_header_t header;
    const void* data;
    size_t data_size;
    uint64_t prog_attach_flags;
} ebpf_extension_data_t;

typedef struct _ebpf_attach_provider_data
{
    ebpf_extension_header_t header;
    ebpf_program_type_t supported_program_type;
    bpf_attach_type_t bpf_attach_type;
    enum bpf_link_type link_type;
} ebpf_attach_provider_data_t;

/***
 * The state of the execution context when the eBPF program was invoked.
 * This is used to cache state that won't change during the execution of
 * the eBPF program and is expensive to query.
 */
typedef struct _ebpf_execution_context_state
{
    epoch_state_t epoch_state;
    union
    {
        uint64_t thread;
        uint32_t cpu;
    } id;
    uint8_t current_irql;
    struct
    {
        const void* next_program;
        uint32_t count;
    } tail_call_state;
} ebpf_execution_context_state_t;

#define EBPF_CONTEXT_HEADER uint64_t context_header[8]
#define EBPF_CONTEXT_HEADER_SIZE (sizeof(uint64_t) * 8)

/**
 * @brief Process map creation notification.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_type The type of map to create.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] value_size The value size requested by the caller in bytes.
 * @param[in] max_entries The maximum number of entries in the map.
 * @param[out] actual_value_size The value size in bytes that will actually be stored in the map.
 * @param[out] map_context Provider-defined per-map context. The eBPF core will pass this back to subsequent map
 *             operations and will eventually pass it to ebpf_postprocess_map_delete_t.
 *
 * Note: When a map lookup happens from user mode, the value is copied into the buffer provided by the user,
 * whereas when a map lookup happens from a BPF program, a pointer to the value is provided to the program,
 * and the program can read or modify the value in place.
 *
 * Therefore, for maps where an extension intends to *modify* the actual value being stored in the map,
 * map CRUD operations from BPF programs are disallowed by the eBPF runtime.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_create_t)(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Out_ uint32_t* actual_value_size,
    _Outptr_ void** map_context);

/**
 * @brief Process a map delete notification.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The map context to delete.
 */
typedef void (*ebpf_postprocess_map_delete_t)(_In_ void* binding_context, _In_ _Post_invalid_ void* map_context);

/**
 * @brief Post-process a found element in a provider-backed map (called after the core lookup).
 *
 * If the provider does not update the original value, i.e., `updates_original_value` is set to false in
 * ebpf_base_map_provider_properties_t, out_value will be NULL and out_value_size will be 0.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Optionally, pointer to the key being looked up.
 * @param[in] in_value_size The size in bytes of the provider's stored value buffer.
 * @param[in] in_value Pointer to the provider's stored value buffer for the entry.
 * @param[in] out_value_size The size in bytes of the output value buffer.
 * @param[out] out_value Optional output buffer to receive the value bytes.
 * @param[in] flags Find flags. Supported values:
 *      EBPF_MAP_OPERATION_HELPER - The lookup is invoked from a BPF program. When this flag is not set, the function
 *      is called in the context of the original user mode process, so the provider may implicitly use the current
 *      process's handle table (e.g., to resolve file descriptors passed as map values).
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 */
typedef ebpf_result_t (*ebpf_postprocess_map_find_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);

/**
 * @brief Pre-process an element update in a provider-backed map (called before the core update).
 *
 * If the provider does not update the original value, i.e., `updates_original_value` is set to false in
 * ebpf_base_map_provider_properties_t, out_value will be NULL and out_value_size will be 0.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key being updated (may be NULL for helper-mode operations, depending on the base map
 *             implementation).
 * @param[in] in_value_size The size in bytes of the input value.
 * @param[in] in_value Pointer to the input value bytes.
 * @param[in] out_value_size The size in bytes of the destination (stored) value buffer.
 * @param[out] out_value Optional pointer to the destination (stored) value buffer to populate.
 * @param[in] flags Update flags. Supported values:
 *      EBPF_MAP_OPERATION_HELPER - The update is invoked from a BPF program. When this flag is not set, the function
 *      is called in the context of the original user mode process, so the provider may implicitly use the current
 *      process's handle table (e.g., to resolve file descriptors passed as map values).
 *
 * @note If this function succeeds but the subsequent core map update fails, the eBPF runtime will call
 *       ebpf_postprocess_map_delete_element_t with the EBPF_MAP_OPERATION_UPDATE flag to allow the provider to
 *       undo any state changes made during this call.
 * @note In a replace operation (updating an existing key), after the core update succeeds,
 *       ebpf_postprocess_map_delete_element_t will be called for the old value being replaced, also with the
 *       EBPF_MAP_OPERATION_UPDATE flag set.
 *
 * IRQL: When EBPF_MAP_OPERATION_HELPER is not set (user-mode caller), this function is called at PASSIVE_LEVEL.
 * Currently, the eBPF runtime blocks map update operations from BPF programs when `updates_original_value` is true,
 * so this callback is not invoked at DISPATCH_LEVEL in that configuration. If `updates_original_value` is false,
 * this callback may be invoked at up to DISPATCH_LEVEL when called from a BPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 * @retval EBPF_NO_MEMORY Unable to allocate memory.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_update_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t in_value_size,
    _In_reads_(in_value_size) const uint8_t* in_value,
    size_t out_value_size,
    _Out_writes_opt_(out_value_size) uint8_t* out_value,
    uint32_t flags);

/**
 * @brief Pre-process an element deletion from a provider-backed map (called before the core delete).
 *
 * @deprecated Use ebpf_postprocess_map_delete_element_t instead. This callback is invoked before the entry is
 * removed from the hash table, under the per-bucket lock. New providers should use
 * ebpf_postprocess_map_delete_element_t, which is invoked after the entry is removed from the hash table.
 * A provider must register exactly one of preprocess_map_delete_element or postprocess_map_delete_element,
 * not both.
 *
 * This function can be called in three scenarios:
 *      1. Normal map element deletion.
 *      2. Deletion performed as part of an update operation (replacing an existing entry).
 *      3. Deletion performed as part of map cleanup.
 * When deletion is part of an update operation, EBPF_MAP_OPERATION_UPDATE is set in the flags parameter.
 * When map cleanup is in progress, EBPF_MAP_OPERATION_MAP_CLEANUP is set in the flags parameter.
 * In both these cases, the provider must not fail the deletion.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key to delete.
 * @param[in] value_size The size in bytes of the provider's stored value buffer.
 * @param[in] value Pointer to the provider's stored value buffer for the entry being deleted.
 * @param[in] flags Delete flags. Possible values:
 *      EBPF_MAP_OPERATION_UPDATE - The delete is invoked as part of an update operation.
 *      EBPF_MAP_OPERATION_MAP_CLEANUP - The delete is invoked as part of a map cleanup operation.
 *      EBPF_MAP_OPERATION_HELPER - The delete is invoked from a BPF program.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 */
typedef __declspec(deprecated("Use ebpf_postprocess_map_delete_element_t instead"))
ebpf_result_t (*ebpf_preprocess_map_delete_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags);

/**
 * @brief Post-process an element deletion from a provider-backed map (called after the core delete).
 *
 * This is the preferred callback for handling element deletions. It is invoked after the entry has been
 * removed from the hash table and after the per-bucket lock has been released. A provider must register
 * exactly one of preprocess_map_delete_element or postprocess_map_delete_element, not both.
 *
 * This function can be called in three scenarios:
 *      1. Normal map element deletion.
 *      2. Deletion performed as part of an update operation (replacing an existing entry).
 *      3. Deletion performed as part of map cleanup.
 * When deletion is part of an update operation, EBPF_MAP_OPERATION_UPDATE is set in the flags parameter.
 * When map cleanup is in progress, EBPF_MAP_OPERATION_MAP_CLEANUP is set in the flags parameter.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key that was deleted.
 * @param[in] value_size The size in bytes of the provider's stored value buffer.
 * @param[in] value Pointer to the provider's stored value buffer for the entry that was deleted.
 * @param[in] flags Delete flags. Possible values:
 *      EBPF_MAP_OPERATION_UPDATE - The delete is invoked as part of an update operation.
 *      EBPF_MAP_OPERATION_MAP_CLEANUP - The delete is invoked as part of a map cleanup operation.
 *      EBPF_MAP_OPERATION_HELPER - The delete is invoked from a BPF program. When this flag is not set, the function
 *      is called in the context of the original user mode process, so the provider may implicitly use the current
 *      process's handle table (e.g., to resolve file descriptors passed as map values).
 *
 * IRQL: When EBPF_MAP_OPERATION_HELPER is not set (user-mode caller), this function is called at PASSIVE_LEVEL.
 * Currently, the eBPF runtime blocks map delete operations from BPF programs when `updates_original_value` is true,
 * so this callback is not invoked at DISPATCH_LEVEL in that configuration. If `updates_original_value` is false,
 * this callback may be invoked at up to DISPATCH_LEVEL when called from a BPF program.
 */
typedef void (*ebpf_postprocess_map_delete_element_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    uint32_t flags);

/**
 * @brief Associate a program type with the map, which allows the map to be used by programs of that type.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] program_type The program type.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_OPERATION_NOT_SUPPORTED The operation is not supported.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_associate_program_type_t)(
    _In_ void* binding_context, _In_ void* map_context, _In_ const ebpf_program_type_t* program_type);

typedef struct _ebpf_base_map_provider_properties
{
    ebpf_extension_header_t header;
    bool updates_original_value; // Whether the provider updates the original value during map operations, which
                                 // controls whether BPF programs can perform map CRUD operations.
} ebpf_base_map_provider_properties_t;

/**
 * Dispatch table implemented by the eBPF extension to provide map operations.
 * This table is used to provide map operations to the eBPF core.
 *
 * A provider must set exactly one of preprocess_map_delete_element (deprecated) or
 * postprocess_map_delete_element (preferred). Setting both or neither is an error.
 * Old providers compiled against the previous SDK will only have preprocess_map_delete_element;
 * the runtime detects this via the header size field and treats postprocess_map_delete_element as NULL.
 */
typedef struct _ebpf_map_provider_dispatch_table
{
    ebpf_extension_header_t header;
    _Notnull_ ebpf_preprocess_map_create_t preprocess_map_create;
    _Notnull_ ebpf_postprocess_map_delete_t postprocess_map_delete;
    _Notnull_ ebpf_preprocess_map_associate_program_type_t preprocess_associate_program_type;
    ebpf_postprocess_map_find_element_t postprocess_map_find_element;
    ebpf_preprocess_map_update_element_t preprocess_map_update_element;
#pragma warning(push)
#pragma warning(disable : 4996) // Suppress deprecation warning for the field declaration itself.
    ebpf_preprocess_map_delete_element_t preprocess_map_delete_element; ///< Deprecated. Use
                                                                        ///< postprocess_map_delete_element instead.
#pragma warning(pop)
    ebpf_postprocess_map_delete_element_t postprocess_map_delete_element; ///< Preferred. Set this instead of
                                                                          ///< preprocess_map_delete_element.
} ebpf_base_map_provider_dispatch_table_t;

/**
 * @brief Mutation operation identity carried through the version 2 mutation token/completion callbacks.
 */
typedef enum _ebpf_map_mutation_operation_v2
{
    EBPF_MAP_MUTATION_OPERATION_UPDATE = 1, ///< The mutation is a map update.
    EBPF_MAP_MUTATION_OPERATION_DELETE = 2, ///< The mutation is a map delete.
} ebpf_map_mutation_operation_v2_t;

/**
 * @brief Reason a version 2 mutation completes. Exactly one completion is delivered for each admitted token.
 */
typedef enum _ebpf_map_mutation_completion_v2
{
    EBPF_MAP_MUTATION_COMPLETION_COMMIT = 1,          ///< Base map operation succeeded.
    EBPF_MAP_MUTATION_COMPLETION_ROLLBACK = 2,        ///< Base map operation failed after admission.
    EBPF_MAP_MUTATION_COMPLETION_PROVIDER_REJECT = 3, ///< Provider rejected after token admission.
} ebpf_map_mutation_completion_v2_t;

/**
 * @brief Version 2 mutation admission callback, invoked before any base-map commit attempt.
 *
 * The provider admits or rejects the mutation and, on admission, returns an opaque mutation token. The eBPF runtime
 * guarantees exactly one matching ebpf_postprocess_map_mutation_complete_v2_t call for every non-NULL token returned.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] operation The mutation operation being admitted.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key being mutated.
 * @param[in] flags Operation flags (see EBPF_MAP_OPERATION_*).
 * @param[out] mutation_token Receives an opaque provider token on admission, or NULL when no completion is required.
 *
 * @retval EBPF_SUCCESS The mutation was admitted.
 * @retval EBPF_ACCESS_DENIED The map does not currently admit mutations.
 * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
 *
 * IRQL: PASSIVE_LEVEL. This callback is never invoked for BPF-program (helper) operations.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_mutation_v2_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    ebpf_map_mutation_operation_v2_t operation,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    uint32_t flags,
    _Outptr_result_maybenull_ void** mutation_token);

/**
 * @brief Version 2 mutation completion callback, invoked exactly once for every non-NULL token returned by
 * ebpf_preprocess_map_mutation_v2_t.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] mutation_token The opaque token returned by ebpf_preprocess_map_mutation_v2_t.
 * @param[in] operation The mutation operation being completed.
 * @param[in] completion Whether the base map operation committed, rolled back, or was rejected by the provider.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key that was mutated.
 * @param[in] value_size The size in bytes of the provider's stored value buffer, or 0 for delete.
 * @param[in] value Pointer to the provider's stored value buffer, or NULL for delete.
 * @param[in] flags Operation flags (see EBPF_MAP_OPERATION_*).
 *
 * IRQL: PASSIVE_LEVEL.
 */
typedef void (*ebpf_postprocess_map_mutation_complete_v2_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    _In_opt_ void* mutation_token,
    ebpf_map_mutation_operation_v2_t operation,
    ebpf_map_mutation_completion_v2_t completion,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_opt_(value_size) const uint8_t* value,
    uint32_t flags);

#define EBPF_MAP_PROVIDER_ACTIVATE_CONTEXT_VERSION_1 1u

/**
 * @brief Activation context wrapper passed by the eBPF runtime to ebpf_preprocess_map_activate_t.
 *
 * provider_attach_context points to the provider-defined activation identity (for CPUMAP, an
 * XDP_EBPF_CPUMAP_ACTIVATE_CONTEXT_V1).
 */
typedef struct _ebpf_map_provider_activate_context_v1
{
    uint16_t size;                         ///< Size of this structure in bytes.
    uint16_t version;                      ///< EBPF_MAP_PROVIDER_ACTIVATE_CONTEXT_VERSION_1.
    ebpf_program_type_t program_type;      ///< Program type driving the activation.
    const void* provider_attach_context;   ///< Provider-defined activation identity.
    uint32_t provider_attach_context_size; ///< Size in bytes of provider_attach_context.
} ebpf_map_provider_activate_context_v1_t;

/**
 * @brief Version 2 activation callback, invoked during attach after mutation admission is closed/drained and before
 * packet data path publication.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] context The activation context wrapper.
 * @param[out] activation_context Receives an opaque provider activation context, passed unchanged to
 * ebpf_postprocess_map_deactivate_t.
 *
 * @retval EBPF_SUCCESS Activation succeeded.
 * @retval EBPF_INVALID_ARGUMENT Wrong version/size or invalid configuration.
 * @retval EBPF_OPERATION_NOT_SUPPORTED Unsupported (e.g., native) mode.
 * @retval EBPF_ACCESS_DENIED The map is not exactly Inactive.
 * @retval EBPF_NO_MEMORY / EBPF_OUT_OF_SPACE Allocation/quota failure.
 * @retval EBPF_FAILED Rollback invariant broken.
 *
 * IRQL: PASSIVE_LEVEL.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_activate_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    _In_ const ebpf_map_provider_activate_context_v1_t* context,
    _Outptr_result_maybenull_ void** activation_context);

/**
 * @brief Version 2 deactivation callback, invoked during detach or rollback in exact reverse activation order.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] activation_context The activation context returned by ebpf_preprocess_map_activate_t.
 *
 * IRQL: PASSIVE_LEVEL.
 */
typedef void (*ebpf_postprocess_map_deactivate_t)(
    _In_ void* binding_context, _In_ void* map_context, _In_opt_ void* activation_context);

/**
 * @brief Version 2 rejectable normal-delete callback. Coexists with postprocess_map_delete_element.
 *
 * Invoked only for normal user-initiated deletes: never for EBPF_MAP_OPERATION_HELPER, EBPF_MAP_OPERATION_UPDATE
 * (replacement), or EBPF_MAP_OPERATION_MAP_CLEANUP. Those keep using postprocess_map_delete_element and must not fail.
 *
 * @param[in] binding_context The binding context provided when the map provider was bound.
 * @param[in] map_context The eBPF map context.
 * @param[in] key_size The size of the key in bytes.
 * @param[in] key Pointer to the key to delete.
 * @param[in] flags Operation flags (see EBPF_MAP_OPERATION_*).
 *
 * @retval EBPF_SUCCESS The delete may proceed.
 * @retval EBPF_ACCESS_DENIED The provider rejects the normal delete.
 *
 * IRQL: PASSIVE_LEVEL.
 */
typedef ebpf_result_t (*ebpf_preprocess_map_delete_element_v2_t)(
    _In_ void* binding_context,
    _In_ void* map_context,
    size_t key_size,
    _In_reads_opt_(key_size) const uint8_t* key,
    uint32_t flags);

/**
 * Version 2 shape of the custom-map provider dispatch table.
 *
 * Field ordering is append-only: every version 1 member keeps its order, and the version 2 members are appended after
 * postprocess_map_delete_element. A version 2 runtime copies min(provider_size, runtime_known_size) as version 1
 * already does, so a version 1 provider table remains valid and the version 2 tail is treated as NULL. A version 1
 * runtime does not understand version 2 and fails closed rather than silently activating.
 */
typedef struct _ebpf_base_map_provider_dispatch_table_v2
{
    ebpf_extension_header_t header;
    _Notnull_ ebpf_preprocess_map_create_t preprocess_map_create;
    _Notnull_ ebpf_postprocess_map_delete_t postprocess_map_delete;
    _Notnull_ ebpf_preprocess_map_associate_program_type_t preprocess_associate_program_type;
    ebpf_postprocess_map_find_element_t postprocess_map_find_element;
    ebpf_preprocess_map_update_element_t preprocess_map_update_element;
#pragma warning(push)
#pragma warning(disable : 4996) // Suppress deprecation warning for the field declaration itself.
    ebpf_preprocess_map_delete_element_t preprocess_map_delete_element; ///< Deprecated. Must be NULL in version 2.
#pragma warning(pop)
    ebpf_postprocess_map_delete_element_t postprocess_map_delete_element; ///< Preferred non-rejectable cleanup.
    ebpf_preprocess_map_mutation_v2_t preprocess_map_mutation_v2;
    ebpf_postprocess_map_mutation_complete_v2_t postprocess_map_mutation_complete_v2;
    ebpf_preprocess_map_activate_t preprocess_map_activate;
    ebpf_postprocess_map_deactivate_t postprocess_map_deactivate;
    ebpf_preprocess_map_delete_element_v2_t preprocess_map_delete_element_v2;
} ebpf_base_map_provider_dispatch_table_v2_t;

/**
 * @brief A referenced custom-map provider handle used by trusted kernel extensions.
 *
 * Obtained from ebpf_program_reference_maps_by_type or ebpf_map_try_reference_provider_context_from_helper and released
 * with ebpf_map_release_provider_reference. Holding the reference keeps the map object alive but intentionally does not
 * expose the provider dispatch table or NMR binding context to the caller.
 */
typedef struct _ebpf_map_provider_reference
{
    const void* map_object;     ///< Opaque referenced map object.
    void* provider_map_context; ///< Provider's per-map context.
    ebpf_map_type_t map_type;   ///< Map type of the referenced map.
} ebpf_map_provider_reference_t;

/**
 * @brief Opaque token that pins a custom-map provider's rundown reference for an entire activation lifetime.
 *
 * Returned by a successful ebpf_map_invoke_provider_activate call and consumed by the matching
 * ebpf_map_invoke_provider_deactivate call. While the token is held, the provider cannot complete unregister/unload,
 * so an activate/deactivate pair can never straddle provider unregister and deactivation can never fail because
 * rundown already began.
 */
typedef struct _ebpf_provider_rundown_token ebpf_provider_rundown_token_t;

/**
 * @brief Allocate memory under epoch control.
 *
 * @param[in] size Size of memory to allocate.
 * @param[in] tag Pool tag to use.
 *
 * @returns Pointer to memory block allocated, or null on failure.
 */
typedef _Ret_writes_maybenull_(size) void* (*ebpf_epoch_allocate_with_tag_t)(size_t size, uint32_t tag);

/**
 * @brief Allocate cache aligned memory under epoch control.
 *
 * @param[in] size Size of memory to allocate.
 * @param[in] tag Pool tag to use.
 *
 * @returns Pointer to memory block allocated, or null on failure.
 */
typedef _Ret_writes_maybenull_(size) void* (*ebpf_epoch_allocate_cache_aligned_with_tag_t)(size_t size, uint32_t tag);

/**
 * @brief Free memory under epoch control.
 * @param[in] memory Allocation to be freed once epoch ends.
 */
typedef void (*ebpf_epoch_free_t)(_In_opt_ _Post_invalid_ void* memory);

/**
 * @brief Free memory under epoch control.
 * @param[in] memory Allocation to be freed once epoch ends.
 */
typedef void (*ebpf_epoch_free_cache_aligned_t)(_In_opt_ _Post_invalid_ void* pointer);

/**
 * @brief Enter an epoch-protected region.
 * @param[in] epoch_state Pointer to epoch state to be filled in. Its size should be at least sizeof(epoch_state_t).
 */
typedef void (*ebpf_epoch_enter_t)(_Out_ void* epoch_state);

/**
 * @brief Exit an epoch-protected region.
 * @param[in] epoch_state Pointer to epoch state returned by epoch_enter_t.
 */
typedef void (*ebpf_epoch_exit_t)(_In_ void* epoch_state);

/**
 * @brief Find an element in an eBPF map (client/runtime helper version).
 *
 * @param[in] map The eBPF map to query.
 * @param[in] key Pointer to the key to search for.
 * @param[out] value Receives a pointer to the value associated with the key.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_KEY_NOT_FOUND The key was not found in the map.
 * @retval EBPF_INVALID_OBJECT An invalid map was provided.
 */
typedef ebpf_result_t (*ebpf_map_find_element_t)(
    _In_ const void* map, _In_ const uint8_t* key, _Outptr_ uint8_t** value);

/**
 * Dispatch table implemented by the eBPF runtime to provide RCU / epoch operations.
 *
 * Notes:
 *
 * Functions `epoch_enter` and `epoch_exit` allow a thread to enter and exit an epoch-protected region,
 * which is necessary when calling the epoch memory operations. These functions are re-entrant, but should
 * always be called in pairs.
 *
 * Below is the list of epoch memory related functions exposed by eBPF runtime:
 * - `epoch_allocate_with_tag`: Allocate memory under epoch control with tag.
 * - `epoch_allocate_cache_aligned_with_tag`: Allocate cache aligned memory under epoch control with tag.
 * - `epoch_free`: Free memory under epoch control.
 * - `epoch_free_cache_aligned`: Free cache aligned memory under epoch control.
 *
 * Each of the above four functions MUST be called within an epoch-protected region (i.e., after ebpf_epoch_enter()
 * and before ebpf_epoch_exit()). Failure to do so may lead to undefined behavior.
 * Provider dispatch function invocations (defined in ebpf_base_map_provider_dispatch_table_t), and BPF helper function
 * callbacks already are epoch-protected, hence these APIs can be directly called in those contexts. If the provider
 * intends to use these APIs outside the above mentioned contexts, it must ensure that the calls are made within an
 * epoch-protected region.
 *
 * Similarly, `find_element_function` can only be invoked in an epoch-protected region, as explained above. Calling it
 * from outside an epoch-protected region may lead to undefined behavior.
 */
typedef struct _ebpf_map_client_dispatch_table
{
    ebpf_extension_header_t header;
    ebpf_map_find_element_t find_element_function;
    ebpf_epoch_enter_t epoch_enter;
    ebpf_epoch_exit_t epoch_exit;
    ebpf_epoch_allocate_with_tag_t epoch_allocate_with_tag;
    ebpf_epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    ebpf_epoch_free_t epoch_free;
    ebpf_epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_base_map_client_dispatch_table_t;

/**
 * @brief Custom map provider data.
 */
typedef struct _ebpf_map_provider_data
{
    ebpf_extension_header_t header;
    uint32_t map_type;                                            ///< Custom map type implemented by the provider.
    uint32_t base_map_type;                                       ///< Base map type used to implement the custom map.
    ebpf_base_map_provider_properties_t* base_properties;         ///< Base map provider properties.
    ebpf_base_map_provider_dispatch_table_t* base_provider_table; ///< Pointer to base map provider dispatch table.
} ebpf_map_provider_data_t;

/**
 * @brief Custom map client data.
 */
typedef struct _ebpf_map_client_data
{
    ebpf_extension_header_t header; ///< Standard extension header containing version and size information.
    uint64_t map_context_offset;    ///< Offset within the map structure where the provider context data is stored.
    ebpf_base_map_client_dispatch_table_t* base_client_table; ///< Pointer to base map client dispatch table.
} ebpf_map_client_data_t;

#define MAP_CONTEXT(map_pointer, offset) ((void**)(((uint8_t*)(map_pointer)) + (offset)))