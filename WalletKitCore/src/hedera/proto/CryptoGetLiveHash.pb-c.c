/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: CryptoGetLiveHash.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "CryptoGetLiveHash.pb-c.h"
void   proto__crypto_get_live_hash_query__init
                     (Proto__CryptoGetLiveHashQuery         *message)
{
  static const Proto__CryptoGetLiveHashQuery init_value = PROTO__CRYPTO_GET_LIVE_HASH_QUERY__INIT;
  *message = init_value;
}
size_t proto__crypto_get_live_hash_query__get_packed_size
                     (const Proto__CryptoGetLiveHashQuery *message)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_query__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__crypto_get_live_hash_query__pack
                     (const Proto__CryptoGetLiveHashQuery *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_query__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__crypto_get_live_hash_query__pack_to_buffer
                     (const Proto__CryptoGetLiveHashQuery *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_query__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__CryptoGetLiveHashQuery *
       proto__crypto_get_live_hash_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__CryptoGetLiveHashQuery *)
     protobuf_c_message_unpack (&proto__crypto_get_live_hash_query__descriptor,
                                allocator, len, data);
}
void   proto__crypto_get_live_hash_query__free_unpacked
                     (Proto__CryptoGetLiveHashQuery *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__crypto_get_live_hash_query__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__crypto_get_live_hash_response__init
                     (Proto__CryptoGetLiveHashResponse         *message)
{
  static const Proto__CryptoGetLiveHashResponse init_value = PROTO__CRYPTO_GET_LIVE_HASH_RESPONSE__INIT;
  *message = init_value;
}
size_t proto__crypto_get_live_hash_response__get_packed_size
                     (const Proto__CryptoGetLiveHashResponse *message)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__crypto_get_live_hash_response__pack
                     (const Proto__CryptoGetLiveHashResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__crypto_get_live_hash_response__pack_to_buffer
                     (const Proto__CryptoGetLiveHashResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__crypto_get_live_hash_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__CryptoGetLiveHashResponse *
       proto__crypto_get_live_hash_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__CryptoGetLiveHashResponse *)
     protobuf_c_message_unpack (&proto__crypto_get_live_hash_response__descriptor,
                                allocator, len, data);
}
void   proto__crypto_get_live_hash_response__free_unpacked
                     (Proto__CryptoGetLiveHashResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__crypto_get_live_hash_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__crypto_get_live_hash_query__field_descriptors[3] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetLiveHashQuery, header),
    &proto__query_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "accountID",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetLiveHashQuery, accountid),
    &proto__account_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetLiveHashQuery, hash),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__crypto_get_live_hash_query__field_indices_by_name[] = {
  1,   /* field[1] = accountID */
  2,   /* field[2] = hash */
  0,   /* field[0] = header */
};
static const ProtobufCIntRange proto__crypto_get_live_hash_query__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor proto__crypto_get_live_hash_query__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.CryptoGetLiveHashQuery",
  "CryptoGetLiveHashQuery",
  "Proto__CryptoGetLiveHashQuery",
  "proto",
  sizeof(Proto__CryptoGetLiveHashQuery),
  3,
  proto__crypto_get_live_hash_query__field_descriptors,
  proto__crypto_get_live_hash_query__field_indices_by_name,
  1,  proto__crypto_get_live_hash_query__number_ranges,
  (ProtobufCMessageInit) proto__crypto_get_live_hash_query__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__crypto_get_live_hash_response__field_descriptors[2] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetLiveHashResponse, header),
    &proto__response_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "liveHash",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetLiveHashResponse, livehash),
    &proto__live_hash__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__crypto_get_live_hash_response__field_indices_by_name[] = {
  0,   /* field[0] = header */
  1,   /* field[1] = liveHash */
};
static const ProtobufCIntRange proto__crypto_get_live_hash_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor proto__crypto_get_live_hash_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.CryptoGetLiveHashResponse",
  "CryptoGetLiveHashResponse",
  "Proto__CryptoGetLiveHashResponse",
  "proto",
  sizeof(Proto__CryptoGetLiveHashResponse),
  2,
  proto__crypto_get_live_hash_response__field_descriptors,
  proto__crypto_get_live_hash_response__field_indices_by_name,
  1,  proto__crypto_get_live_hash_response__number_ranges,
  (ProtobufCMessageInit) proto__crypto_get_live_hash_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
