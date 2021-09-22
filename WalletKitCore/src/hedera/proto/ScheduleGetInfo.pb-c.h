/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ScheduleGetInfo.proto */

#ifndef PROTOBUF_C_ScheduleGetInfo_2eproto__INCLUDED
#define PROTOBUF_C_ScheduleGetInfo_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "BasicTypes.pb-c.h"
#include "Timestamp.pb-c.h"
#include "QueryHeader.pb-c.h"
#include "ResponseHeader.pb-c.h"
#include "SchedulableTransactionBody.pb-c.h"

typedef struct Proto__ScheduleGetInfoQuery Proto__ScheduleGetInfoQuery;
typedef struct Proto__ScheduleInfo Proto__ScheduleInfo;
typedef struct Proto__ScheduleGetInfoResponse Proto__ScheduleGetInfoResponse;


/* --- enums --- */


/* --- messages --- */

/*
 *Gets information about a schedule in the network's action queue.
 *Responds with <tt>INVALID_SCHEDULE_ID</tt> if the requested schedule doesn't exist.
 */
struct  Proto__ScheduleGetInfoQuery
{
  ProtobufCMessage base;
  /*
   * standard info sent from client to node including the signed payment, and what kind of response is requested (cost, state proof, both, or neither).
   */
  Proto__QueryHeader *header;
  /*
   * The id of the schedule to interrogate
   */
  Proto__ScheduleID *scheduleid;
};
#define PROTO__SCHEDULE_GET_INFO_QUERY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__schedule_get_info_query__descriptor) \
    , NULL, NULL }


typedef enum {
  PROTO__SCHEDULE_INFO__DATA__NOT_SET = 0,
  PROTO__SCHEDULE_INFO__DATA_DELETION_TIME = 2,
  PROTO__SCHEDULE_INFO__DATA_EXECUTION_TIME = 3
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(PROTO__SCHEDULE_INFO__DATA__CASE)
} Proto__ScheduleInfo__DataCase;

/*
 *Information summarizing schedule state 
 */
struct  Proto__ScheduleInfo
{
  ProtobufCMessage base;
  /*
   * The id of the schedule
   */
  Proto__ScheduleID *scheduleid;
  /*
   * The time at which the schedule will expire
   */
  Proto__Timestamp *expirationtime;
  /*
   * The scheduled transaction
   */
  Proto__SchedulableTransactionBody *scheduledtransactionbody;
  /*
   * The publicly visible memo of the schedule
   */
  char *memo;
  /*
   * The key used to delete the schedule from state
   */
  Proto__Key *adminkey;
  /*
   * The Ed25519 keys the network deems to have signed the scheduled transaction
   */
  Proto__KeyList *signers;
  /*
   * The id of the account that created the schedule
   */
  Proto__AccountID *creatoraccountid;
  /*
   * The id of the account responsible for the service fee of the scheduled transaction
   */
  Proto__AccountID *payeraccountid;
  /*
   * The transaction id that will be used in the record of the scheduled transaction (if it executes)
   */
  Proto__TransactionID *scheduledtransactionid;
  Proto__ScheduleInfo__DataCase data_case;
  union {
    /*
     * If the schedule has been deleted, the consensus time when this occurred
     */
    Proto__Timestamp *deletion_time;
    /*
     * If the schedule has been executed, the consensus time when this occurred
     */
    Proto__Timestamp *execution_time;
  };
};
#define PROTO__SCHEDULE_INFO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__schedule_info__descriptor) \
    , NULL, NULL, NULL, (char *)protobuf_c_empty_string, NULL, NULL, NULL, NULL, NULL, PROTO__SCHEDULE_INFO__DATA__NOT_SET, {0} }


/*
 *Response wrapper for the <tt>ScheduleInfo</tt>
 */
struct  Proto__ScheduleGetInfoResponse
{
  ProtobufCMessage base;
  /*
   * Standard response from node to client, including the requested fields: cost, or state proof, or both, or neither
   */
  Proto__ResponseHeader *header;
  /*
   * The information requested about this schedule instance
   */
  Proto__ScheduleInfo *scheduleinfo;
};
#define PROTO__SCHEDULE_GET_INFO_RESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__schedule_get_info_response__descriptor) \
    , NULL, NULL }


/* Proto__ScheduleGetInfoQuery methods */
void   proto__schedule_get_info_query__init
                     (Proto__ScheduleGetInfoQuery         *message);
size_t proto__schedule_get_info_query__get_packed_size
                     (const Proto__ScheduleGetInfoQuery   *message);
size_t proto__schedule_get_info_query__pack
                     (const Proto__ScheduleGetInfoQuery   *message,
                      uint8_t             *out);
size_t proto__schedule_get_info_query__pack_to_buffer
                     (const Proto__ScheduleGetInfoQuery   *message,
                      ProtobufCBuffer     *buffer);
Proto__ScheduleGetInfoQuery *
       proto__schedule_get_info_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__schedule_get_info_query__free_unpacked
                     (Proto__ScheduleGetInfoQuery *message,
                      ProtobufCAllocator *allocator);
/* Proto__ScheduleInfo methods */
void   proto__schedule_info__init
                     (Proto__ScheduleInfo         *message);
size_t proto__schedule_info__get_packed_size
                     (const Proto__ScheduleInfo   *message);
size_t proto__schedule_info__pack
                     (const Proto__ScheduleInfo   *message,
                      uint8_t             *out);
size_t proto__schedule_info__pack_to_buffer
                     (const Proto__ScheduleInfo   *message,
                      ProtobufCBuffer     *buffer);
Proto__ScheduleInfo *
       proto__schedule_info__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__schedule_info__free_unpacked
                     (Proto__ScheduleInfo *message,
                      ProtobufCAllocator *allocator);
/* Proto__ScheduleGetInfoResponse methods */
void   proto__schedule_get_info_response__init
                     (Proto__ScheduleGetInfoResponse         *message);
size_t proto__schedule_get_info_response__get_packed_size
                     (const Proto__ScheduleGetInfoResponse   *message);
size_t proto__schedule_get_info_response__pack
                     (const Proto__ScheduleGetInfoResponse   *message,
                      uint8_t             *out);
size_t proto__schedule_get_info_response__pack_to_buffer
                     (const Proto__ScheduleGetInfoResponse   *message,
                      ProtobufCBuffer     *buffer);
Proto__ScheduleGetInfoResponse *
       proto__schedule_get_info_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__schedule_get_info_response__free_unpacked
                     (Proto__ScheduleGetInfoResponse *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Proto__ScheduleGetInfoQuery_Closure)
                 (const Proto__ScheduleGetInfoQuery *message,
                  void *closure_data);
typedef void (*Proto__ScheduleInfo_Closure)
                 (const Proto__ScheduleInfo *message,
                  void *closure_data);
typedef void (*Proto__ScheduleGetInfoResponse_Closure)
                 (const Proto__ScheduleGetInfoResponse *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor proto__schedule_get_info_query__descriptor;
extern const ProtobufCMessageDescriptor proto__schedule_info__descriptor;
extern const ProtobufCMessageDescriptor proto__schedule_get_info_response__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_ScheduleGetInfo_2eproto__INCLUDED */
