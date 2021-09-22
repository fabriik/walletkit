/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ConsensusGetTopicInfo.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "ConsensusGetTopicInfo.pb-c.h"
void   proto__consensus_get_topic_info_query__init
                     (Proto__ConsensusGetTopicInfoQuery         *message)
{
  static const Proto__ConsensusGetTopicInfoQuery init_value = PROTO__CONSENSUS_GET_TOPIC_INFO_QUERY__INIT;
  *message = init_value;
}
size_t proto__consensus_get_topic_info_query__get_packed_size
                     (const Proto__ConsensusGetTopicInfoQuery *message)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_query__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__consensus_get_topic_info_query__pack
                     (const Proto__ConsensusGetTopicInfoQuery *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_query__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__consensus_get_topic_info_query__pack_to_buffer
                     (const Proto__ConsensusGetTopicInfoQuery *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_query__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ConsensusGetTopicInfoQuery *
       proto__consensus_get_topic_info_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ConsensusGetTopicInfoQuery *)
     protobuf_c_message_unpack (&proto__consensus_get_topic_info_query__descriptor,
                                allocator, len, data);
}
void   proto__consensus_get_topic_info_query__free_unpacked
                     (Proto__ConsensusGetTopicInfoQuery *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__consensus_get_topic_info_query__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__consensus_get_topic_info_response__init
                     (Proto__ConsensusGetTopicInfoResponse         *message)
{
  static const Proto__ConsensusGetTopicInfoResponse init_value = PROTO__CONSENSUS_GET_TOPIC_INFO_RESPONSE__INIT;
  *message = init_value;
}
size_t proto__consensus_get_topic_info_response__get_packed_size
                     (const Proto__ConsensusGetTopicInfoResponse *message)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__consensus_get_topic_info_response__pack
                     (const Proto__ConsensusGetTopicInfoResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__consensus_get_topic_info_response__pack_to_buffer
                     (const Proto__ConsensusGetTopicInfoResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__consensus_get_topic_info_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ConsensusGetTopicInfoResponse *
       proto__consensus_get_topic_info_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ConsensusGetTopicInfoResponse *)
     protobuf_c_message_unpack (&proto__consensus_get_topic_info_response__descriptor,
                                allocator, len, data);
}
void   proto__consensus_get_topic_info_response__free_unpacked
                     (Proto__ConsensusGetTopicInfoResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__consensus_get_topic_info_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__consensus_get_topic_info_query__field_descriptors[2] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusGetTopicInfoQuery, header),
    &proto__query_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "topicID",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusGetTopicInfoQuery, topicid),
    &proto__topic_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__consensus_get_topic_info_query__field_indices_by_name[] = {
  0,   /* field[0] = header */
  1,   /* field[1] = topicID */
};
static const ProtobufCIntRange proto__consensus_get_topic_info_query__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor proto__consensus_get_topic_info_query__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ConsensusGetTopicInfoQuery",
  "ConsensusGetTopicInfoQuery",
  "Proto__ConsensusGetTopicInfoQuery",
  "proto",
  sizeof(Proto__ConsensusGetTopicInfoQuery),
  2,
  proto__consensus_get_topic_info_query__field_descriptors,
  proto__consensus_get_topic_info_query__field_indices_by_name,
  1,  proto__consensus_get_topic_info_query__number_ranges,
  (ProtobufCMessageInit) proto__consensus_get_topic_info_query__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__consensus_get_topic_info_response__field_descriptors[3] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusGetTopicInfoResponse, header),
    &proto__response_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "topicID",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusGetTopicInfoResponse, topicid),
    &proto__topic_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "topicInfo",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ConsensusGetTopicInfoResponse, topicinfo),
    &proto__consensus_topic_info__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__consensus_get_topic_info_response__field_indices_by_name[] = {
  0,   /* field[0] = header */
  1,   /* field[1] = topicID */
  2,   /* field[2] = topicInfo */
};
static const ProtobufCIntRange proto__consensus_get_topic_info_response__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 5, 2 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor proto__consensus_get_topic_info_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ConsensusGetTopicInfoResponse",
  "ConsensusGetTopicInfoResponse",
  "Proto__ConsensusGetTopicInfoResponse",
  "proto",
  sizeof(Proto__ConsensusGetTopicInfoResponse),
  3,
  proto__consensus_get_topic_info_response__field_descriptors,
  proto__consensus_get_topic_info_response__field_indices_by_name,
  2,  proto__consensus_get_topic_info_response__number_ranges,
  (ProtobufCMessageInit) proto__consensus_get_topic_info_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
