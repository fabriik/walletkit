/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: NetworkGetVersionInfo.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "NetworkGetVersionInfo.pb-c.h"
void   proto__network_get_version_info_query__init
                     (Proto__NetworkGetVersionInfoQuery         *message)
{
  static const Proto__NetworkGetVersionInfoQuery init_value = PROTO__NETWORK_GET_VERSION_INFO_QUERY__INIT;
  *message = init_value;
}
size_t proto__network_get_version_info_query__get_packed_size
                     (const Proto__NetworkGetVersionInfoQuery *message)
{
  assert(message->base.descriptor == &proto__network_get_version_info_query__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__network_get_version_info_query__pack
                     (const Proto__NetworkGetVersionInfoQuery *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__network_get_version_info_query__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__network_get_version_info_query__pack_to_buffer
                     (const Proto__NetworkGetVersionInfoQuery *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__network_get_version_info_query__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__NetworkGetVersionInfoQuery *
       proto__network_get_version_info_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__NetworkGetVersionInfoQuery *)
     protobuf_c_message_unpack (&proto__network_get_version_info_query__descriptor,
                                allocator, len, data);
}
void   proto__network_get_version_info_query__free_unpacked
                     (Proto__NetworkGetVersionInfoQuery *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__network_get_version_info_query__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__network_get_version_info_response__init
                     (Proto__NetworkGetVersionInfoResponse         *message)
{
  static const Proto__NetworkGetVersionInfoResponse init_value = PROTO__NETWORK_GET_VERSION_INFO_RESPONSE__INIT;
  *message = init_value;
}
size_t proto__network_get_version_info_response__get_packed_size
                     (const Proto__NetworkGetVersionInfoResponse *message)
{
  assert(message->base.descriptor == &proto__network_get_version_info_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__network_get_version_info_response__pack
                     (const Proto__NetworkGetVersionInfoResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__network_get_version_info_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__network_get_version_info_response__pack_to_buffer
                     (const Proto__NetworkGetVersionInfoResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__network_get_version_info_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__NetworkGetVersionInfoResponse *
       proto__network_get_version_info_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__NetworkGetVersionInfoResponse *)
     protobuf_c_message_unpack (&proto__network_get_version_info_response__descriptor,
                                allocator, len, data);
}
void   proto__network_get_version_info_response__free_unpacked
                     (Proto__NetworkGetVersionInfoResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__network_get_version_info_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__network_get_version_info_query__field_descriptors[1] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__NetworkGetVersionInfoQuery, header),
    &proto__query_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__network_get_version_info_query__field_indices_by_name[] = {
  0,   /* field[0] = header */
};
static const ProtobufCIntRange proto__network_get_version_info_query__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor proto__network_get_version_info_query__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.NetworkGetVersionInfoQuery",
  "NetworkGetVersionInfoQuery",
  "Proto__NetworkGetVersionInfoQuery",
  "proto",
  sizeof(Proto__NetworkGetVersionInfoQuery),
  1,
  proto__network_get_version_info_query__field_descriptors,
  proto__network_get_version_info_query__field_indices_by_name,
  1,  proto__network_get_version_info_query__number_ranges,
  (ProtobufCMessageInit) proto__network_get_version_info_query__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__network_get_version_info_response__field_descriptors[3] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__NetworkGetVersionInfoResponse, header),
    &proto__response_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hapiProtoVersion",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__NetworkGetVersionInfoResponse, hapiprotoversion),
    &proto__semantic_version__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hederaServicesVersion",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__NetworkGetVersionInfoResponse, hederaservicesversion),
    &proto__semantic_version__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__network_get_version_info_response__field_indices_by_name[] = {
  1,   /* field[1] = hapiProtoVersion */
  0,   /* field[0] = header */
  2,   /* field[2] = hederaServicesVersion */
};
static const ProtobufCIntRange proto__network_get_version_info_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor proto__network_get_version_info_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.NetworkGetVersionInfoResponse",
  "NetworkGetVersionInfoResponse",
  "Proto__NetworkGetVersionInfoResponse",
  "proto",
  sizeof(Proto__NetworkGetVersionInfoResponse),
  3,
  proto__network_get_version_info_response__field_descriptors,
  proto__network_get_version_info_response__field_indices_by_name,
  1,  proto__network_get_version_info_response__number_ranges,
  (ProtobufCMessageInit) proto__network_get_version_info_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
