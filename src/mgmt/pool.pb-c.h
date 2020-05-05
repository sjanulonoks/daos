/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: pool.proto */

#ifndef PROTOBUF_C_pool_2eproto__INCLUDED
#define PROTOBUF_C_pool_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Mgmt__PoolCreateReq Mgmt__PoolCreateReq;
typedef struct _Mgmt__PoolCreateResp Mgmt__PoolCreateResp;
typedef struct _Mgmt__PoolDestroyReq Mgmt__PoolDestroyReq;
typedef struct _Mgmt__PoolDestroyResp Mgmt__PoolDestroyResp;
typedef struct _Mgmt__PoolExcludeReq Mgmt__PoolExcludeReq;
typedef struct _Mgmt__PoolExcludeResp Mgmt__PoolExcludeResp;
typedef struct _Mgmt__PoolReintegrateReq Mgmt__PoolReintegrateReq;
typedef struct _Mgmt__PoolReintegrateResp Mgmt__PoolReintegrateResp;
typedef struct _Mgmt__ListPoolsReq Mgmt__ListPoolsReq;
typedef struct _Mgmt__ListPoolsResp Mgmt__ListPoolsResp;
typedef struct _Mgmt__ListPoolsResp__Pool Mgmt__ListPoolsResp__Pool;
typedef struct _Mgmt__ListContReq Mgmt__ListContReq;
typedef struct _Mgmt__ListContResp Mgmt__ListContResp;
typedef struct _Mgmt__ListContResp__Cont Mgmt__ListContResp__Cont;
typedef struct _Mgmt__PoolQueryReq Mgmt__PoolQueryReq;
typedef struct _Mgmt__StorageUsageStats Mgmt__StorageUsageStats;
typedef struct _Mgmt__PoolRebuildStatus Mgmt__PoolRebuildStatus;
typedef struct _Mgmt__PoolSetPropReq Mgmt__PoolSetPropReq;
typedef struct _Mgmt__PoolSetPropResp Mgmt__PoolSetPropResp;
typedef struct _Mgmt__PoolQueryResp Mgmt__PoolQueryResp;


/* --- enums --- */

typedef enum _Mgmt__PoolRebuildStatus__State {
  MGMT__POOL_REBUILD_STATUS__STATE__IDLE = 0,
  MGMT__POOL_REBUILD_STATUS__STATE__DONE = 1,
  MGMT__POOL_REBUILD_STATUS__STATE__BUSY = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MGMT__POOL_REBUILD_STATUS__STATE)
} Mgmt__PoolRebuildStatus__State;

/* --- messages --- */

/*
 * PoolCreateReq supplies new pool parameters.
 */
struct  _Mgmt__PoolCreateReq
{
  ProtobufCMessage base;
  /*
   * SCM size in bytes
   */
  uint64_t scmbytes;
  /*
   * NVMe size in bytes
   */
  uint64_t nvmebytes;
  /*
   * target ranks
   */
  size_t n_ranks;
  uint32_t *ranks;
  /*
   * desired number of pool service replicas
   */
  uint32_t numsvcreps;
  /*
   * formatted user e.g. "bob@"
   */
  char *user;
  /*
   * formatted group e.g. "builders@"
   */
  char *usergroup;
  /*
   * UUID for new pool, generated on the client
   */
  char *uuid;
  /*
   * DAOS system identifier
   */
  char *sys;
  /*
   * Access Control Entries in short string format
   */
  size_t n_acl;
  char **acl;
};
#define MGMT__POOL_CREATE_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_create_req__descriptor) \
    , 0, 0, 0,NULL, 0, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, 0,NULL }


/*
 * PoolCreateResp returns created pool uuid and ranks.
 */
struct  _Mgmt__PoolCreateResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  /*
   * pool service replica ranks
   */
  size_t n_svcreps;
  uint32_t *svcreps;
};
#define MGMT__POOL_CREATE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_create_resp__descriptor) \
    , 0, 0,NULL }


/*
 * PoolDestroyReq supplies pool identifier and force flag.
 */
struct  _Mgmt__PoolDestroyReq
{
  ProtobufCMessage base;
  /*
   * uuid of pool to destroy
   */
  char *uuid;
  /*
   * DAOS system identifier
   */
  char *sys;
  /*
   * destroy regardless of active connections
   */
  protobuf_c_boolean force;
};
#define MGMT__POOL_DESTROY_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_destroy_req__descriptor) \
    , (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, 0 }


/*
 * PoolDestroyResp returns resultant state of destroy operation.
 */
struct  _Mgmt__PoolDestroyResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
};
#define MGMT__POOL_DESTROY_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_destroy_resp__descriptor) \
    , 0 }


/*
 * PoolExcludeReq supplies pool identifier, rank, and target_idxs.
 */
struct  _Mgmt__PoolExcludeReq
{
  ProtobufCMessage base;
  /*
   * uuid of pool to add target up to
   */
  char *uuid;
  /*
   * target to move to the up state
   */
  uint32_t rank;
  /*
   * target ranks
   */
  size_t n_targetidx;
  uint32_t *targetidx;
};
#define MGMT__POOL_EXCLUDE_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_exclude_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0, 0,NULL }


/*
 * PoolExcludeResp returns resultant state of Exclude operation.
 */
struct  _Mgmt__PoolExcludeResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
};
#define MGMT__POOL_EXCLUDE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_exclude_resp__descriptor) \
    , 0 }


/*
 * PoolReintegrateReq supplies pool identifier, rank, and target_idxs.
 */
struct  _Mgmt__PoolReintegrateReq
{
  ProtobufCMessage base;
  /*
   * uuid of pool to add target up to
   */
  char *uuid;
  /*
   * target to move to the up state
   */
  uint32_t rank;
  /*
   * target ranks
   */
  size_t n_targetidx;
  uint32_t *targetidx;
};
#define MGMT__POOL_REINTEGRATE_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_reintegrate_req__descriptor) \
    , (char *)protobuf_c_empty_string, 0, 0,NULL }


/*
 * PoolReintegrateResp returns resultant state of Reintegrate operation.
 */
struct  _Mgmt__PoolReintegrateResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
};
#define MGMT__POOL_REINTEGRATE_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_reintegrate_resp__descriptor) \
    , 0 }


/*
 * ListPoolsReq represents a request to list pools on a given DAOS system.
 */
struct  _Mgmt__ListPoolsReq
{
  ProtobufCMessage base;
  /*
   * DAOS system identifier
   */
  char *sys;
};
#define MGMT__LIST_POOLS_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_pools_req__descriptor) \
    , (char *)protobuf_c_empty_string }


struct  _Mgmt__ListPoolsResp__Pool
{
  ProtobufCMessage base;
  /*
   * uuid of pool
   */
  char *uuid;
  /*
   * pool service replica ranks
   */
  size_t n_svcreps;
  uint32_t *svcreps;
};
#define MGMT__LIST_POOLS_RESP__POOL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_pools_resp__pool__descriptor) \
    , (char *)protobuf_c_empty_string, 0,NULL }


/*
 * ListPoolsResp returns the list of pools in the system.
 */
struct  _Mgmt__ListPoolsResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  /*
   * pools list
   */
  size_t n_pools;
  Mgmt__ListPoolsResp__Pool **pools;
};
#define MGMT__LIST_POOLS_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_pools_resp__descriptor) \
    , 0, 0,NULL }


/*
 * ListContainers
 * Initial implementation differs from C API
 * (numContainers not provided in request - get whole list)
 */
struct  _Mgmt__ListContReq
{
  ProtobufCMessage base;
  /*
   * uuid of pool
   */
  char *uuid;
};
#define MGMT__LIST_CONT_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_cont_req__descriptor) \
    , (char *)protobuf_c_empty_string }


struct  _Mgmt__ListContResp__Cont
{
  ProtobufCMessage base;
  /*
   * uuid of container
   */
  char *uuid;
};
#define MGMT__LIST_CONT_RESP__CONT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_cont_resp__cont__descriptor) \
    , (char *)protobuf_c_empty_string }


struct  _Mgmt__ListContResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  /*
   * containers
   */
  size_t n_containers;
  Mgmt__ListContResp__Cont **containers;
};
#define MGMT__LIST_CONT_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__list_cont_resp__descriptor) \
    , 0, 0,NULL }


/*
 * PoolQueryReq represents a pool query request.
 */
struct  _Mgmt__PoolQueryReq
{
  ProtobufCMessage base;
  char *uuid;
};
#define MGMT__POOL_QUERY_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_query_req__descriptor) \
    , (char *)protobuf_c_empty_string }


/*
 * StorageUsageStats represents usage statistics for a storage subsystem.
 */
struct  _Mgmt__StorageUsageStats
{
  ProtobufCMessage base;
  uint64_t total;
  uint64_t free;
  uint64_t min;
  uint64_t max;
  uint64_t mean;
};
#define MGMT__STORAGE_USAGE_STATS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__storage_usage_stats__descriptor) \
    , 0, 0, 0, 0, 0 }


/*
 * PoolRebuildStatus represents a pool's rebuild status.
 */
struct  _Mgmt__PoolRebuildStatus
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  Mgmt__PoolRebuildStatus__State state;
  uint64_t objects;
  uint64_t records;
};
#define MGMT__POOL_REBUILD_STATUS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_rebuild_status__descriptor) \
    , 0, MGMT__POOL_REBUILD_STATUS__STATE__IDLE, 0, 0 }


typedef enum {
  MGMT__POOL_SET_PROP_REQ__PROPERTY__NOT_SET = 0,
  MGMT__POOL_SET_PROP_REQ__PROPERTY_NAME = 2,
  MGMT__POOL_SET_PROP_REQ__PROPERTY_NUMBER = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MGMT__POOL_SET_PROP_REQ__PROPERTY)
} Mgmt__PoolSetPropReq__PropertyCase;

typedef enum {
  MGMT__POOL_SET_PROP_REQ__VALUE__NOT_SET = 0,
  MGMT__POOL_SET_PROP_REQ__VALUE_STRVAL = 4,
  MGMT__POOL_SET_PROP_REQ__VALUE_NUMVAL = 5
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MGMT__POOL_SET_PROP_REQ__VALUE)
} Mgmt__PoolSetPropReq__ValueCase;

/*
 * PoolSetPropReq represents a request to set a pool property.
 */
struct  _Mgmt__PoolSetPropReq
{
  ProtobufCMessage base;
  /*
   * uuid of pool to modify
   */
  char *uuid;
  Mgmt__PoolSetPropReq__PropertyCase property_case;
  union {
    /*
     * pool property name
     */
    char *name;
    /*
     * pool property enum
     */
    uint32_t number;
  };
  Mgmt__PoolSetPropReq__ValueCase value_case;
  union {
    /*
     * pool property string value
     */
    char *strval;
    /*
     * pool property numeric value
     */
    uint64_t numval;
  };
};
#define MGMT__POOL_SET_PROP_REQ__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_set_prop_req__descriptor) \
    , (char *)protobuf_c_empty_string, MGMT__POOL_SET_PROP_REQ__PROPERTY__NOT_SET, {0}, MGMT__POOL_SET_PROP_REQ__VALUE__NOT_SET, {0} }


typedef enum {
  MGMT__POOL_SET_PROP_RESP__PROPERTY__NOT_SET = 0,
  MGMT__POOL_SET_PROP_RESP__PROPERTY_NAME = 2,
  MGMT__POOL_SET_PROP_RESP__PROPERTY_NUMBER = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MGMT__POOL_SET_PROP_RESP__PROPERTY)
} Mgmt__PoolSetPropResp__PropertyCase;

typedef enum {
  MGMT__POOL_SET_PROP_RESP__VALUE__NOT_SET = 0,
  MGMT__POOL_SET_PROP_RESP__VALUE_STRVAL = 4,
  MGMT__POOL_SET_PROP_RESP__VALUE_NUMVAL = 5
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(MGMT__POOL_SET_PROP_RESP__VALUE)
} Mgmt__PoolSetPropResp__ValueCase;

/*
 * PoolSetPropResp represents the result of setting a property.
 */
struct  _Mgmt__PoolSetPropResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  Mgmt__PoolSetPropResp__PropertyCase property_case;
  union {
    /*
     * pool property name
     */
    char *name;
    /*
     * pool property enum
     */
    uint32_t number;
  };
  Mgmt__PoolSetPropResp__ValueCase value_case;
  union {
    /*
     * pool property string value
     */
    char *strval;
    /*
     * pool property numeric value
     */
    uint64_t numval;
  };
};
#define MGMT__POOL_SET_PROP_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_set_prop_resp__descriptor) \
    , 0, MGMT__POOL_SET_PROP_RESP__PROPERTY__NOT_SET, {0}, MGMT__POOL_SET_PROP_RESP__VALUE__NOT_SET, {0} }


/*
 * PoolQueryResp represents a pool query response.
 */
struct  _Mgmt__PoolQueryResp
{
  ProtobufCMessage base;
  /*
   * DAOS error code
   */
  int32_t status;
  /*
   * pool uuid
   */
  char *uuid;
  /*
   * total targets in pool
   */
  uint32_t totaltargets;
  /*
   * active targets in pool
   */
  uint32_t activetargets;
  /*
   * number of disabled targets in pool
   */
  uint32_t disabledtargets;
  /*
   * pool rebuild status
   */
  Mgmt__PoolRebuildStatus *rebuild;
  /*
   * SCM storage usage stats
   */
  Mgmt__StorageUsageStats *scm;
  /*
   * NVMe storage usage stats
   */
  Mgmt__StorageUsageStats *nvme;
};
#define MGMT__POOL_QUERY_RESP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&mgmt__pool_query_resp__descriptor) \
    , 0, (char *)protobuf_c_empty_string, 0, 0, 0, NULL, NULL, NULL }


/* Mgmt__PoolCreateReq methods */
void   mgmt__pool_create_req__init
                     (Mgmt__PoolCreateReq         *message);
size_t mgmt__pool_create_req__get_packed_size
                     (const Mgmt__PoolCreateReq   *message);
size_t mgmt__pool_create_req__pack
                     (const Mgmt__PoolCreateReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_create_req__pack_to_buffer
                     (const Mgmt__PoolCreateReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolCreateReq *
       mgmt__pool_create_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_create_req__free_unpacked
                     (Mgmt__PoolCreateReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolCreateResp methods */
void   mgmt__pool_create_resp__init
                     (Mgmt__PoolCreateResp         *message);
size_t mgmt__pool_create_resp__get_packed_size
                     (const Mgmt__PoolCreateResp   *message);
size_t mgmt__pool_create_resp__pack
                     (const Mgmt__PoolCreateResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_create_resp__pack_to_buffer
                     (const Mgmt__PoolCreateResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolCreateResp *
       mgmt__pool_create_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_create_resp__free_unpacked
                     (Mgmt__PoolCreateResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolDestroyReq methods */
void   mgmt__pool_destroy_req__init
                     (Mgmt__PoolDestroyReq         *message);
size_t mgmt__pool_destroy_req__get_packed_size
                     (const Mgmt__PoolDestroyReq   *message);
size_t mgmt__pool_destroy_req__pack
                     (const Mgmt__PoolDestroyReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_destroy_req__pack_to_buffer
                     (const Mgmt__PoolDestroyReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolDestroyReq *
       mgmt__pool_destroy_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_destroy_req__free_unpacked
                     (Mgmt__PoolDestroyReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolDestroyResp methods */
void   mgmt__pool_destroy_resp__init
                     (Mgmt__PoolDestroyResp         *message);
size_t mgmt__pool_destroy_resp__get_packed_size
                     (const Mgmt__PoolDestroyResp   *message);
size_t mgmt__pool_destroy_resp__pack
                     (const Mgmt__PoolDestroyResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_destroy_resp__pack_to_buffer
                     (const Mgmt__PoolDestroyResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolDestroyResp *
       mgmt__pool_destroy_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_destroy_resp__free_unpacked
                     (Mgmt__PoolDestroyResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolExcludeReq methods */
void   mgmt__pool_exclude_req__init
                     (Mgmt__PoolExcludeReq         *message);
size_t mgmt__pool_exclude_req__get_packed_size
                     (const Mgmt__PoolExcludeReq   *message);
size_t mgmt__pool_exclude_req__pack
                     (const Mgmt__PoolExcludeReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_exclude_req__pack_to_buffer
                     (const Mgmt__PoolExcludeReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolExcludeReq *
       mgmt__pool_exclude_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_exclude_req__free_unpacked
                     (Mgmt__PoolExcludeReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolExcludeResp methods */
void   mgmt__pool_exclude_resp__init
                     (Mgmt__PoolExcludeResp         *message);
size_t mgmt__pool_exclude_resp__get_packed_size
                     (const Mgmt__PoolExcludeResp   *message);
size_t mgmt__pool_exclude_resp__pack
                     (const Mgmt__PoolExcludeResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_exclude_resp__pack_to_buffer
                     (const Mgmt__PoolExcludeResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolExcludeResp *
       mgmt__pool_exclude_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_exclude_resp__free_unpacked
                     (Mgmt__PoolExcludeResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolReintegrateReq methods */
void   mgmt__pool_reintegrate_req__init
                     (Mgmt__PoolReintegrateReq         *message);
size_t mgmt__pool_reintegrate_req__get_packed_size
                     (const Mgmt__PoolReintegrateReq   *message);
size_t mgmt__pool_reintegrate_req__pack
                     (const Mgmt__PoolReintegrateReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_reintegrate_req__pack_to_buffer
                     (const Mgmt__PoolReintegrateReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolReintegrateReq *
       mgmt__pool_reintegrate_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_reintegrate_req__free_unpacked
                     (Mgmt__PoolReintegrateReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolReintegrateResp methods */
void   mgmt__pool_reintegrate_resp__init
                     (Mgmt__PoolReintegrateResp         *message);
size_t mgmt__pool_reintegrate_resp__get_packed_size
                     (const Mgmt__PoolReintegrateResp   *message);
size_t mgmt__pool_reintegrate_resp__pack
                     (const Mgmt__PoolReintegrateResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_reintegrate_resp__pack_to_buffer
                     (const Mgmt__PoolReintegrateResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolReintegrateResp *
       mgmt__pool_reintegrate_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_reintegrate_resp__free_unpacked
                     (Mgmt__PoolReintegrateResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__ListPoolsReq methods */
void   mgmt__list_pools_req__init
                     (Mgmt__ListPoolsReq         *message);
size_t mgmt__list_pools_req__get_packed_size
                     (const Mgmt__ListPoolsReq   *message);
size_t mgmt__list_pools_req__pack
                     (const Mgmt__ListPoolsReq   *message,
                      uint8_t             *out);
size_t mgmt__list_pools_req__pack_to_buffer
                     (const Mgmt__ListPoolsReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__ListPoolsReq *
       mgmt__list_pools_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__list_pools_req__free_unpacked
                     (Mgmt__ListPoolsReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__ListPoolsResp__Pool methods */
void   mgmt__list_pools_resp__pool__init
                     (Mgmt__ListPoolsResp__Pool         *message);
/* Mgmt__ListPoolsResp methods */
void   mgmt__list_pools_resp__init
                     (Mgmt__ListPoolsResp         *message);
size_t mgmt__list_pools_resp__get_packed_size
                     (const Mgmt__ListPoolsResp   *message);
size_t mgmt__list_pools_resp__pack
                     (const Mgmt__ListPoolsResp   *message,
                      uint8_t             *out);
size_t mgmt__list_pools_resp__pack_to_buffer
                     (const Mgmt__ListPoolsResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__ListPoolsResp *
       mgmt__list_pools_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__list_pools_resp__free_unpacked
                     (Mgmt__ListPoolsResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__ListContReq methods */
void   mgmt__list_cont_req__init
                     (Mgmt__ListContReq         *message);
size_t mgmt__list_cont_req__get_packed_size
                     (const Mgmt__ListContReq   *message);
size_t mgmt__list_cont_req__pack
                     (const Mgmt__ListContReq   *message,
                      uint8_t             *out);
size_t mgmt__list_cont_req__pack_to_buffer
                     (const Mgmt__ListContReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__ListContReq *
       mgmt__list_cont_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__list_cont_req__free_unpacked
                     (Mgmt__ListContReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__ListContResp__Cont methods */
void   mgmt__list_cont_resp__cont__init
                     (Mgmt__ListContResp__Cont         *message);
/* Mgmt__ListContResp methods */
void   mgmt__list_cont_resp__init
                     (Mgmt__ListContResp         *message);
size_t mgmt__list_cont_resp__get_packed_size
                     (const Mgmt__ListContResp   *message);
size_t mgmt__list_cont_resp__pack
                     (const Mgmt__ListContResp   *message,
                      uint8_t             *out);
size_t mgmt__list_cont_resp__pack_to_buffer
                     (const Mgmt__ListContResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__ListContResp *
       mgmt__list_cont_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__list_cont_resp__free_unpacked
                     (Mgmt__ListContResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolQueryReq methods */
void   mgmt__pool_query_req__init
                     (Mgmt__PoolQueryReq         *message);
size_t mgmt__pool_query_req__get_packed_size
                     (const Mgmt__PoolQueryReq   *message);
size_t mgmt__pool_query_req__pack
                     (const Mgmt__PoolQueryReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_query_req__pack_to_buffer
                     (const Mgmt__PoolQueryReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolQueryReq *
       mgmt__pool_query_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_query_req__free_unpacked
                     (Mgmt__PoolQueryReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__StorageUsageStats methods */
void   mgmt__storage_usage_stats__init
                     (Mgmt__StorageUsageStats         *message);
size_t mgmt__storage_usage_stats__get_packed_size
                     (const Mgmt__StorageUsageStats   *message);
size_t mgmt__storage_usage_stats__pack
                     (const Mgmt__StorageUsageStats   *message,
                      uint8_t             *out);
size_t mgmt__storage_usage_stats__pack_to_buffer
                     (const Mgmt__StorageUsageStats   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__StorageUsageStats *
       mgmt__storage_usage_stats__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__storage_usage_stats__free_unpacked
                     (Mgmt__StorageUsageStats *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolRebuildStatus methods */
void   mgmt__pool_rebuild_status__init
                     (Mgmt__PoolRebuildStatus         *message);
size_t mgmt__pool_rebuild_status__get_packed_size
                     (const Mgmt__PoolRebuildStatus   *message);
size_t mgmt__pool_rebuild_status__pack
                     (const Mgmt__PoolRebuildStatus   *message,
                      uint8_t             *out);
size_t mgmt__pool_rebuild_status__pack_to_buffer
                     (const Mgmt__PoolRebuildStatus   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolRebuildStatus *
       mgmt__pool_rebuild_status__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_rebuild_status__free_unpacked
                     (Mgmt__PoolRebuildStatus *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolSetPropReq methods */
void   mgmt__pool_set_prop_req__init
                     (Mgmt__PoolSetPropReq         *message);
size_t mgmt__pool_set_prop_req__get_packed_size
                     (const Mgmt__PoolSetPropReq   *message);
size_t mgmt__pool_set_prop_req__pack
                     (const Mgmt__PoolSetPropReq   *message,
                      uint8_t             *out);
size_t mgmt__pool_set_prop_req__pack_to_buffer
                     (const Mgmt__PoolSetPropReq   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolSetPropReq *
       mgmt__pool_set_prop_req__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_set_prop_req__free_unpacked
                     (Mgmt__PoolSetPropReq *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolSetPropResp methods */
void   mgmt__pool_set_prop_resp__init
                     (Mgmt__PoolSetPropResp         *message);
size_t mgmt__pool_set_prop_resp__get_packed_size
                     (const Mgmt__PoolSetPropResp   *message);
size_t mgmt__pool_set_prop_resp__pack
                     (const Mgmt__PoolSetPropResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_set_prop_resp__pack_to_buffer
                     (const Mgmt__PoolSetPropResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolSetPropResp *
       mgmt__pool_set_prop_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_set_prop_resp__free_unpacked
                     (Mgmt__PoolSetPropResp *message,
                      ProtobufCAllocator *allocator);
/* Mgmt__PoolQueryResp methods */
void   mgmt__pool_query_resp__init
                     (Mgmt__PoolQueryResp         *message);
size_t mgmt__pool_query_resp__get_packed_size
                     (const Mgmt__PoolQueryResp   *message);
size_t mgmt__pool_query_resp__pack
                     (const Mgmt__PoolQueryResp   *message,
                      uint8_t             *out);
size_t mgmt__pool_query_resp__pack_to_buffer
                     (const Mgmt__PoolQueryResp   *message,
                      ProtobufCBuffer     *buffer);
Mgmt__PoolQueryResp *
       mgmt__pool_query_resp__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   mgmt__pool_query_resp__free_unpacked
                     (Mgmt__PoolQueryResp *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Mgmt__PoolCreateReq_Closure)
                 (const Mgmt__PoolCreateReq *message,
                  void *closure_data);
typedef void (*Mgmt__PoolCreateResp_Closure)
                 (const Mgmt__PoolCreateResp *message,
                  void *closure_data);
typedef void (*Mgmt__PoolDestroyReq_Closure)
                 (const Mgmt__PoolDestroyReq *message,
                  void *closure_data);
typedef void (*Mgmt__PoolDestroyResp_Closure)
                 (const Mgmt__PoolDestroyResp *message,
                  void *closure_data);
typedef void (*Mgmt__PoolExcludeReq_Closure)
                 (const Mgmt__PoolExcludeReq *message,
                  void *closure_data);
typedef void (*Mgmt__PoolExcludeResp_Closure)
                 (const Mgmt__PoolExcludeResp *message,
                  void *closure_data);
typedef void (*Mgmt__PoolReintegrateReq_Closure)
                 (const Mgmt__PoolReintegrateReq *message,
                  void *closure_data);
typedef void (*Mgmt__PoolReintegrateResp_Closure)
                 (const Mgmt__PoolReintegrateResp *message,
                  void *closure_data);
typedef void (*Mgmt__ListPoolsReq_Closure)
                 (const Mgmt__ListPoolsReq *message,
                  void *closure_data);
typedef void (*Mgmt__ListPoolsResp__Pool_Closure)
                 (const Mgmt__ListPoolsResp__Pool *message,
                  void *closure_data);
typedef void (*Mgmt__ListPoolsResp_Closure)
                 (const Mgmt__ListPoolsResp *message,
                  void *closure_data);
typedef void (*Mgmt__ListContReq_Closure)
                 (const Mgmt__ListContReq *message,
                  void *closure_data);
typedef void (*Mgmt__ListContResp__Cont_Closure)
                 (const Mgmt__ListContResp__Cont *message,
                  void *closure_data);
typedef void (*Mgmt__ListContResp_Closure)
                 (const Mgmt__ListContResp *message,
                  void *closure_data);
typedef void (*Mgmt__PoolQueryReq_Closure)
                 (const Mgmt__PoolQueryReq *message,
                  void *closure_data);
typedef void (*Mgmt__StorageUsageStats_Closure)
                 (const Mgmt__StorageUsageStats *message,
                  void *closure_data);
typedef void (*Mgmt__PoolRebuildStatus_Closure)
                 (const Mgmt__PoolRebuildStatus *message,
                  void *closure_data);
typedef void (*Mgmt__PoolSetPropReq_Closure)
                 (const Mgmt__PoolSetPropReq *message,
                  void *closure_data);
typedef void (*Mgmt__PoolSetPropResp_Closure)
                 (const Mgmt__PoolSetPropResp *message,
                  void *closure_data);
typedef void (*Mgmt__PoolQueryResp_Closure)
                 (const Mgmt__PoolQueryResp *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor mgmt__pool_create_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_create_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_destroy_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_destroy_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_exclude_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_exclude_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_reintegrate_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_reintegrate_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_pools_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_pools_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_pools_resp__pool__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_cont_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_cont_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__list_cont_resp__cont__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_query_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__storage_usage_stats__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_rebuild_status__descriptor;
extern const ProtobufCEnumDescriptor    mgmt__pool_rebuild_status__state__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_set_prop_req__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_set_prop_resp__descriptor;
extern const ProtobufCMessageDescriptor mgmt__pool_query_resp__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_pool_2eproto__INCLUDED */
