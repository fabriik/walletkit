/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: UncheckedSubmit.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "UncheckedSubmit.pb-c.h"
void   proto__unchecked_submit_body__init
                     (Proto__UncheckedSubmitBody         *message)
{
  static const Proto__UncheckedSubmitBody init_value = PROTO__UNCHECKED_SUBMIT_BODY__INIT;
  *message = init_value;
}
size_t proto__unchecked_submit_body__get_packed_size
                     (const Proto__UncheckedSubmitBody *message)
{
  assert(message->base.descriptor == &proto__unchecked_submit_body__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__unchecked_submit_body__pack
                     (const Proto__UncheckedSubmitBody *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__unchecked_submit_body__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__unchecked_submit_body__pack_to_buffer
                     (const Proto__UncheckedSubmitBody *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__unchecked_submit_body__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__UncheckedSubmitBody *
       proto__unchecked_submit_body__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__UncheckedSubmitBody *)
     protobuf_c_message_unpack (&proto__unchecked_submit_body__descriptor,
                                allocator, len, data);
}
void   proto__unchecked_submit_body__free_unpacked
                     (Proto__UncheckedSubmitBody *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__unchecked_submit_body__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__unchecked_submit_body__field_descriptors[1] =
{
  {
    "transactionBytes",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__UncheckedSubmitBody, transactionbytes),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__unchecked_submit_body__field_indices_by_name[] = {
  0,   /* field[0] = transactionBytes */
};
static const ProtobufCIntRange proto__unchecked_submit_body__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor proto__unchecked_submit_body__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.UncheckedSubmitBody",
  "UncheckedSubmitBody",
  "Proto__UncheckedSubmitBody",
  "proto",
  sizeof(Proto__UncheckedSubmitBody),
  1,
  proto__unchecked_submit_body__field_descriptors,
  proto__unchecked_submit_body__field_indices_by_name,
  1,  proto__unchecked_submit_body__number_ranges,
  (ProtobufCMessageInit) proto__unchecked_submit_body__init,
  NULL,NULL,NULL    /* reserved[123] */
};
