/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: CryptoGetAccountRecords.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "CryptoGetAccountRecords.pb-c.h"
void   proto__crypto_get_account_records_query__init
                     (Proto__CryptoGetAccountRecordsQuery         *message)
{
  static const Proto__CryptoGetAccountRecordsQuery init_value = PROTO__CRYPTO_GET_ACCOUNT_RECORDS_QUERY__INIT;
  *message = init_value;
}
size_t proto__crypto_get_account_records_query__get_packed_size
                     (const Proto__CryptoGetAccountRecordsQuery *message)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_query__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__crypto_get_account_records_query__pack
                     (const Proto__CryptoGetAccountRecordsQuery *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_query__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__crypto_get_account_records_query__pack_to_buffer
                     (const Proto__CryptoGetAccountRecordsQuery *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_query__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__CryptoGetAccountRecordsQuery *
       proto__crypto_get_account_records_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__CryptoGetAccountRecordsQuery *)
     protobuf_c_message_unpack (&proto__crypto_get_account_records_query__descriptor,
                                allocator, len, data);
}
void   proto__crypto_get_account_records_query__free_unpacked
                     (Proto__CryptoGetAccountRecordsQuery *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__crypto_get_account_records_query__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__crypto_get_account_records_response__init
                     (Proto__CryptoGetAccountRecordsResponse         *message)
{
  static const Proto__CryptoGetAccountRecordsResponse init_value = PROTO__CRYPTO_GET_ACCOUNT_RECORDS_RESPONSE__INIT;
  *message = init_value;
}
size_t proto__crypto_get_account_records_response__get_packed_size
                     (const Proto__CryptoGetAccountRecordsResponse *message)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__crypto_get_account_records_response__pack
                     (const Proto__CryptoGetAccountRecordsResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__crypto_get_account_records_response__pack_to_buffer
                     (const Proto__CryptoGetAccountRecordsResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__crypto_get_account_records_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__CryptoGetAccountRecordsResponse *
       proto__crypto_get_account_records_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__CryptoGetAccountRecordsResponse *)
     protobuf_c_message_unpack (&proto__crypto_get_account_records_response__descriptor,
                                allocator, len, data);
}
void   proto__crypto_get_account_records_response__free_unpacked
                     (Proto__CryptoGetAccountRecordsResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__crypto_get_account_records_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__crypto_get_account_records_query__field_descriptors[2] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetAccountRecordsQuery, header),
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
    offsetof(Proto__CryptoGetAccountRecordsQuery, accountid),
    &proto__account_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__crypto_get_account_records_query__field_indices_by_name[] = {
  1,   /* field[1] = accountID */
  0,   /* field[0] = header */
};
static const ProtobufCIntRange proto__crypto_get_account_records_query__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor proto__crypto_get_account_records_query__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.CryptoGetAccountRecordsQuery",
  "CryptoGetAccountRecordsQuery",
  "Proto__CryptoGetAccountRecordsQuery",
  "proto",
  sizeof(Proto__CryptoGetAccountRecordsQuery),
  2,
  proto__crypto_get_account_records_query__field_descriptors,
  proto__crypto_get_account_records_query__field_indices_by_name,
  1,  proto__crypto_get_account_records_query__number_ranges,
  (ProtobufCMessageInit) proto__crypto_get_account_records_query__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__crypto_get_account_records_response__field_descriptors[3] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__CryptoGetAccountRecordsResponse, header),
    &proto__response_header__descriptor,
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
    offsetof(Proto__CryptoGetAccountRecordsResponse, accountid),
    &proto__account_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "records",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__CryptoGetAccountRecordsResponse, n_records),
    offsetof(Proto__CryptoGetAccountRecordsResponse, records),
    &proto__transaction_record__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__crypto_get_account_records_response__field_indices_by_name[] = {
  1,   /* field[1] = accountID */
  0,   /* field[0] = header */
  2,   /* field[2] = records */
};
static const ProtobufCIntRange proto__crypto_get_account_records_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor proto__crypto_get_account_records_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.CryptoGetAccountRecordsResponse",
  "CryptoGetAccountRecordsResponse",
  "Proto__CryptoGetAccountRecordsResponse",
  "proto",
  sizeof(Proto__CryptoGetAccountRecordsResponse),
  3,
  proto__crypto_get_account_records_response__field_descriptors,
  proto__crypto_get_account_records_response__field_indices_by_name,
  1,  proto__crypto_get_account_records_response__number_ranges,
  (ProtobufCMessageInit) proto__crypto_get_account_records_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
