/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: TransactionContents.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "TransactionContents.pb-c.h"
void   proto__signed_transaction__init
                     (Proto__SignedTransaction         *message)
{
  static const Proto__SignedTransaction init_value = PROTO__SIGNED_TRANSACTION__INIT;
  *message = init_value;
}
size_t proto__signed_transaction__get_packed_size
                     (const Proto__SignedTransaction *message)
{
  assert(message->base.descriptor == &proto__signed_transaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t proto__signed_transaction__pack
                     (const Proto__SignedTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &proto__signed_transaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t proto__signed_transaction__pack_to_buffer
                     (const Proto__SignedTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &proto__signed_transaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Proto__SignedTransaction *
       proto__signed_transaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Proto__SignedTransaction *)
     protobuf_c_message_unpack (&proto__signed_transaction__descriptor,
                                allocator, len, data);
}
void   proto__signed_transaction__free_unpacked
                     (Proto__SignedTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &proto__signed_transaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor proto__signed_transaction__field_descriptors[2] =
{
  {
    "bodyBytes",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Proto__SignedTransaction, bodybytes),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "sigMap",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Proto__SignedTransaction, sigmap),
    &proto__signature_map__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned proto__signed_transaction__field_indices_by_name[] = {
  0,   /* field[0] = bodyBytes */
  1,   /* field[1] = sigMap */
};
static const ProtobufCIntRange proto__signed_transaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor proto__signed_transaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "proto.SignedTransaction",
  "SignedTransaction",
  "Proto__SignedTransaction",
  "proto",
  sizeof(Proto__SignedTransaction),
  2,
  proto__signed_transaction__field_descriptors,
  proto__signed_transaction__field_indices_by_name,
  1,  proto__signed_transaction__number_ranges,
  (ProtobufCMessageInit) proto__signed_transaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
