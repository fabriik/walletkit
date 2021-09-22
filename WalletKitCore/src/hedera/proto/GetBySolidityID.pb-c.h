/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: GetBySolidityID.proto */

#ifndef PROTOBUF_C_GetBySolidityID_2eproto__INCLUDED
#define PROTOBUF_C_GetBySolidityID_2eproto__INCLUDED

#include "protobuf-c.h"

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1004000 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "BasicTypes.pb-c.h"
#include "QueryHeader.pb-c.h"
#include "ResponseHeader.pb-c.h"

typedef struct Proto__GetBySolidityIDQuery Proto__GetBySolidityIDQuery;
typedef struct Proto__GetBySolidityIDResponse Proto__GetBySolidityIDResponse;


/* --- enums --- */


/* --- messages --- */

/*
 * Get the IDs in the format used by transactions, given the ID in the format used by Solidity. If the Solidity ID is for a smart contract instance, then both the ContractID and associated AccountID will be returned. 
 */
struct  Proto__GetBySolidityIDQuery
{
  ProtobufCMessage base;
  /*
   * Standard info sent from client to node, including the signed payment, and what kind of response is requested (cost, state proof, both, or neither).
   */
  Proto__QueryHeader *header;
  /*
   * The ID in the format used by Solidity
   */
  char *solidityid;
};
#define PROTO__GET_BY_SOLIDITY_IDQUERY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__get_by_solidity_idquery__descriptor) \
    , NULL, (char *)protobuf_c_empty_string }


/*
 * Response when the client sends the node GetBySolidityIDQuery 
 */
struct  Proto__GetBySolidityIDResponse
{
  ProtobufCMessage base;
  /*
   * Standard response from node to client, including the requested fields: cost, or state proof, or both, or neither
   */
  Proto__ResponseHeader *header;
  /*
   *  The Account ID for the cryptocurrency account
   */
  Proto__AccountID *accountid;
  /*
   * The file Id for the file
   */
  Proto__FileID *fileid;
  /*
   * A smart contract ID for the instance (if this is included, then the associated accountID will also be included)
   */
  Proto__ContractID *contractid;
};
#define PROTO__GET_BY_SOLIDITY_IDRESPONSE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&proto__get_by_solidity_idresponse__descriptor) \
    , NULL, NULL, NULL, NULL }


/* Proto__GetBySolidityIDQuery methods */
void   proto__get_by_solidity_idquery__init
                     (Proto__GetBySolidityIDQuery         *message);
size_t proto__get_by_solidity_idquery__get_packed_size
                     (const Proto__GetBySolidityIDQuery   *message);
size_t proto__get_by_solidity_idquery__pack
                     (const Proto__GetBySolidityIDQuery   *message,
                      uint8_t             *out);
size_t proto__get_by_solidity_idquery__pack_to_buffer
                     (const Proto__GetBySolidityIDQuery   *message,
                      ProtobufCBuffer     *buffer);
Proto__GetBySolidityIDQuery *
       proto__get_by_solidity_idquery__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__get_by_solidity_idquery__free_unpacked
                     (Proto__GetBySolidityIDQuery *message,
                      ProtobufCAllocator *allocator);
/* Proto__GetBySolidityIDResponse methods */
void   proto__get_by_solidity_idresponse__init
                     (Proto__GetBySolidityIDResponse         *message);
size_t proto__get_by_solidity_idresponse__get_packed_size
                     (const Proto__GetBySolidityIDResponse   *message);
size_t proto__get_by_solidity_idresponse__pack
                     (const Proto__GetBySolidityIDResponse   *message,
                      uint8_t             *out);
size_t proto__get_by_solidity_idresponse__pack_to_buffer
                     (const Proto__GetBySolidityIDResponse   *message,
                      ProtobufCBuffer     *buffer);
Proto__GetBySolidityIDResponse *
       proto__get_by_solidity_idresponse__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   proto__get_by_solidity_idresponse__free_unpacked
                     (Proto__GetBySolidityIDResponse *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Proto__GetBySolidityIDQuery_Closure)
                 (const Proto__GetBySolidityIDQuery *message,
                  void *closure_data);
typedef void (*Proto__GetBySolidityIDResponse_Closure)
                 (const Proto__GetBySolidityIDResponse *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor proto__get_by_solidity_idquery__descriptor;
extern const ProtobufCMessageDescriptor proto__get_by_solidity_idresponse__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_GetBySolidityID_2eproto__INCLUDED */
