/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: ContractCallLocal.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "ContractCallLocal.pb-c.h"
void   proto__contract_loginfo__init
                     (Proto__ContractLoginfo         *message)
{
  static const Proto__ContractLoginfo init_value = PROTO__CONTRACT_LOGINFO__INIT;
  *message = init_value;
}
size_t proto__contract_loginfo__get_packed_size
                     (const Proto__ContractLoginfo *message)
{
  assert(message->base.descriptor == &proto__contract_loginfo__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__contract_loginfo__pack
                     (const Proto__ContractLoginfo *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__contract_loginfo__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__contract_loginfo__pack_to_buffer
                     (const Proto__ContractLoginfo *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__contract_loginfo__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ContractLoginfo *
       proto__contract_loginfo__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ContractLoginfo *)
     protobuf_c_message_unpack (&proto__contract_loginfo__descriptor,
                                allocator, len, data);
}
void   proto__contract_loginfo__free_unpacked
                     (Proto__ContractLoginfo *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__contract_loginfo__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__contract_function_result__init
                     (Proto__ContractFunctionResult         *message)
{
  static const Proto__ContractFunctionResult init_value = PROTO__CONTRACT_FUNCTION_RESULT__INIT;
  *message = init_value;
}
size_t proto__contract_function_result__get_packed_size
                     (const Proto__ContractFunctionResult *message)
{
  assert(message->base.descriptor == &proto__contract_function_result__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__contract_function_result__pack
                     (const Proto__ContractFunctionResult *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__contract_function_result__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__contract_function_result__pack_to_buffer
                     (const Proto__ContractFunctionResult *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__contract_function_result__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ContractFunctionResult *
       proto__contract_function_result__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ContractFunctionResult *)
     protobuf_c_message_unpack (&proto__contract_function_result__descriptor,
                                allocator, len, data);
}
void   proto__contract_function_result__free_unpacked
                     (Proto__ContractFunctionResult *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__contract_function_result__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__contract_call_local_query__init
                     (Proto__ContractCallLocalQuery         *message)
{
  static const Proto__ContractCallLocalQuery init_value = PROTO__CONTRACT_CALL_LOCAL_QUERY__INIT;
  *message = init_value;
}
size_t proto__contract_call_local_query__get_packed_size
                     (const Proto__ContractCallLocalQuery *message)
{
  assert(message->base.descriptor == &proto__contract_call_local_query__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__contract_call_local_query__pack
                     (const Proto__ContractCallLocalQuery *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__contract_call_local_query__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__contract_call_local_query__pack_to_buffer
                     (const Proto__ContractCallLocalQuery *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__contract_call_local_query__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ContractCallLocalQuery *
       proto__contract_call_local_query__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ContractCallLocalQuery *)
     protobuf_c_message_unpack (&proto__contract_call_local_query__descriptor,
                                allocator, len, data);
}
void   proto__contract_call_local_query__free_unpacked
                     (Proto__ContractCallLocalQuery *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__contract_call_local_query__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   proto__contract_call_local_response__init
                     (Proto__ContractCallLocalResponse         *message)
{
  static const Proto__ContractCallLocalResponse init_value = PROTO__CONTRACT_CALL_LOCAL_RESPONSE__INIT;
  *message = init_value;
}
size_t proto__contract_call_local_response__get_packed_size
                     (const Proto__ContractCallLocalResponse *message)
{
  assert(message->base.descriptor == &proto__contract_call_local_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__contract_call_local_response__pack
                     (const Proto__ContractCallLocalResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__contract_call_local_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__contract_call_local_response__pack_to_buffer
                     (const Proto__ContractCallLocalResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__contract_call_local_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__ContractCallLocalResponse *
       proto__contract_call_local_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__ContractCallLocalResponse *)
     protobuf_c_message_unpack (&proto__contract_call_local_response__descriptor,
                                allocator, len, data);
}
void   proto__contract_call_local_response__free_unpacked
                     (Proto__ContractCallLocalResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__contract_call_local_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__contract_loginfo__field_descriptors[4] =
{
  {
    "contractID",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractLoginfo, contractid),
    &proto__contract_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bloom",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractLoginfo, bloom),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "topic",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_BYTES,
    offsetof(Proto__ContractLoginfo, n_topic),
    offsetof(Proto__ContractLoginfo, topic),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "data",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractLoginfo, data),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__contract_loginfo__field_indices_by_name[] = {
  1,   /* field[1] = bloom */
  0,   /* field[0] = contractID */
  3,   /* field[3] = data */
  2,   /* field[2] = topic */
};
static const ProtobufCIntRange proto__contract_loginfo__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor proto__contract_loginfo__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ContractLoginfo",
  "ContractLoginfo",
  "Proto__ContractLoginfo",
  "proto",
  sizeof(Proto__ContractLoginfo),
  4,
  proto__contract_loginfo__field_descriptors,
  proto__contract_loginfo__field_indices_by_name,
  1,  proto__contract_loginfo__number_ranges,
  (ProtobufCMessageInit) proto__contract_loginfo__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__contract_function_result__field_descriptors[7] =
{
  {
    "contractID",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractFunctionResult, contractid),
    &proto__contract_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractCallResult",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractFunctionResult, contractcallresult),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "errorMessage",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractFunctionResult, errormessage),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bloom",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractFunctionResult, bloom),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gasUsed",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractFunctionResult, gasused),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "logInfo",
    6,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__ContractFunctionResult, n_loginfo),
    offsetof(Proto__ContractFunctionResult, loginfo),
    &proto__contract_loginfo__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "createdContractIDs",
    7,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Proto__ContractFunctionResult, n_createdcontractids),
    offsetof(Proto__ContractFunctionResult, createdcontractids),
    &proto__contract_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__contract_function_result__field_indices_by_name[] = {
  3,   /* field[3] = bloom */
  1,   /* field[1] = contractCallResult */
  0,   /* field[0] = contractID */
  6,   /* field[6] = createdContractIDs */
  2,   /* field[2] = errorMessage */
  4,   /* field[4] = gasUsed */
  5,   /* field[5] = logInfo */
};
static const ProtobufCIntRange proto__contract_function_result__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 7 }
};
const ProtobufCMessageDescriptor proto__contract_function_result__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ContractFunctionResult",
  "ContractFunctionResult",
  "Proto__ContractFunctionResult",
  "proto",
  sizeof(Proto__ContractFunctionResult),
  7,
  proto__contract_function_result__field_descriptors,
  proto__contract_function_result__field_indices_by_name,
  1,  proto__contract_function_result__number_ranges,
  (ProtobufCMessageInit) proto__contract_function_result__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__contract_call_local_query__field_descriptors[5] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalQuery, header),
    &proto__query_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "contractID",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalQuery, contractid),
    &proto__contract_id__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "gas",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalQuery, gas),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "functionParameters",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalQuery, functionparameters),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "maxResultSize",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT64,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalQuery, maxresultsize),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__contract_call_local_query__field_indices_by_name[] = {
  1,   /* field[1] = contractID */
  3,   /* field[3] = functionParameters */
  2,   /* field[2] = gas */
  0,   /* field[0] = header */
  4,   /* field[4] = maxResultSize */
};
static const ProtobufCIntRange proto__contract_call_local_query__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 5 }
};
const ProtobufCMessageDescriptor proto__contract_call_local_query__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ContractCallLocalQuery",
  "ContractCallLocalQuery",
  "Proto__ContractCallLocalQuery",
  "proto",
  sizeof(Proto__ContractCallLocalQuery),
  5,
  proto__contract_call_local_query__field_descriptors,
  proto__contract_call_local_query__field_indices_by_name,
  1,  proto__contract_call_local_query__number_ranges,
  (ProtobufCMessageInit) proto__contract_call_local_query__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor proto__contract_call_local_response__field_descriptors[2] =
{
  {
    "header",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalResponse, header),
    &proto__response_header__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "functionResult",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__ContractCallLocalResponse, functionresult),
    &proto__contract_function_result__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__contract_call_local_response__field_indices_by_name[] = {
  1,   /* field[1] = functionResult */
  0,   /* field[0] = header */
};
static const ProtobufCIntRange proto__contract_call_local_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor proto__contract_call_local_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.ContractCallLocalResponse",
  "ContractCallLocalResponse",
  "Proto__ContractCallLocalResponse",
  "proto",
  sizeof(Proto__ContractCallLocalResponse),
  2,
  proto__contract_call_local_response__field_descriptors,
  proto__contract_call_local_response__field_indices_by_name,
  1,  proto__contract_call_local_response__number_ranges,
  (ProtobufCMessageInit) proto__contract_call_local_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
