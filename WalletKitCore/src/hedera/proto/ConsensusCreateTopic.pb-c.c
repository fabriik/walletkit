/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ConsensusCreateTopic.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "ConsensusCreateTopic.pb-c.h"
void   proto__consensus_create_topic_transaction_body__init
                     (Proto__ConsensusCreateTopicTransactionBody         *message)
{
  static const Proto__ConsensusCreateTopicTransactionBody init_value = PROTO__CONSENSUS_CREATE_TOPIC_TRANSACTION_BODY__INIT;
  *message = init_value;
}
size_t proto__consensus_create_topic_transaction_body__get_packed_size
                     (const Proto__ConsensusCreateTopicTransactionBody *message)
{
  assert(message->base.descriptor == &proto__consensus_create_topic_transaction_body__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__consensus_create_topic_transaction_body__pack
                     (const Proto__ConsensusCreateTopicTransactionBody *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__consensus_create_topic_transaction_body__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__consensus_create_topic_transaction_body__pack_to_buffer
                     (const Proto__ConsensusCreateTopicTransactionBody *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__consensus_create_topic_transaction_body__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ConsensusCreateTopicTransactionBody *
       proto__consensus_create_topic_transaction_body__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ConsensusCreateTopicTransactionBody *)
     protobuf_c_message_unpack (&proto__consensus_create_topic_transaction_body__descriptor,
                                allocator, len, data);
}
void   proto__consensus_create_topic_transaction_body__free_unpacked
                     (Proto__ConsensusCreateTopicTransactionBody *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__consensus_create_topic_transaction_body__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__consensus_create_topic_transaction_body__field_descriptors[5] =
{
  {
    "memo",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusCreateTopicTransactionBody, memo),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "adminKey",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusCreateTopicTransactionBody, adminkey),
    &proto__key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "submitKey",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusCreateTopicTransactionBody, submitkey),
    &proto__key__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "autoRenewPeriod",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusCreateTopicTransactionBody, autorenewperiod),
    &proto__duration__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "autoRenewAccount",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusCreateTopicTransactionBody, autorenewaccount),
    &proto__account_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__consensus_create_topic_transaction_body__field_indices_by_name[] = {
  1,   /* field[1] = adminKey */
  4,   /* field[4] = autoRenewAccount */
  3,   /* field[3] = autoRenewPeriod */
  0,   /* field[0] = memo */
  2,   /* field[2] = submitKey */
};
static const ProtobufCIntRange proto__consensus_create_topic_transaction_body__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 6, 3 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor proto__consensus_create_topic_transaction_body__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ConsensusCreateTopicTransactionBody",
  "ConsensusCreateTopicTransactionBody",
  "Proto__ConsensusCreateTopicTransactionBody",
  "proto",
  sizeof(Proto__ConsensusCreateTopicTransactionBody),
  5,
  proto__consensus_create_topic_transaction_body__field_descriptors,
  proto__consensus_create_topic_transaction_body__field_indices_by_name,
  2,  proto__consensus_create_topic_transaction_body__number_ranges,
  (ProtobufCMessageInit) proto__consensus_create_topic_transaction_body__init,
  NULL,NULL,NULL    /* reserved[123] */
};
