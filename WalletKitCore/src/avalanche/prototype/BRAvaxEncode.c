//
//  File.c
//  
//
//  Created by Amit on 17/08/2021.
//

#include "BRAvaxEncode.h"
#include "support/BRInt.h"

#if !defined (MIN)
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#define AVAX_X_COMPACT_SIG_SIZE (65)

struct OutputBuffer{
    uint8_t * bytes;
    size_t len;
};

int outputBufferCompare(struct OutputBuffer * v1, struct OutputBuffer * v2)
{
    int compare = memcmp(v1->bytes, v2->bytes, MIN(v1->len, v2->len));
    return compare;
}

int ouputBufferCompareHelper(const void * i1, const void * i2){
    struct OutputBuffer * v1 = (struct OutputBuffer *)i1;
    struct OutputBuffer * v2 = (struct OutputBuffer *)i2;
    return outputBufferCompare(v1, v2);
}

int freeOutputBuffers(BRArrayOf(struct OutputBuffer) buffers){
    for(int i=0; i < array_count(buffers); i++){
        free(buffers[i].bytes);
    }
}


/*
 Inputs is an array of transferable input objects. Inputs must be sorted and unique. Inputs are sorted first lexicographically by their TxID and then by the UTXOIndex from low to high. If there are inputs that have the same TxID and UTXOIndex, then the transaction is invalid as this would result in a double spend.
 */
int inputBufferCompare(struct TransferableInputRecord * v1, struct TransferableInputRecord * v2)
{
//    uint8_t buffer1[32+4];
//    uint8_t buffer2[32+4];
//    size_t offset=0;
//    UInt256Set(&buffer1[offset], v1->tx.id);
//    UInt256Set(&buffer2[offset], v2->tx.id);
//    offset+=32;
//    UInt32SetBE(&buffer1[offset], v1->utxo_index);
//    UInt32SetBE(&buffer2[offset], v2->utxo_index);
//    int compare = memcmp(buffer1,buffer2, 36);
//    return compare;
    
    //Note:memcmp does lexographic sort , not sure what UInt256Eq will do
    int compare = memcmp(&v1->tx.id.u8[0], &v2->tx.id.u8[0], 32);
    if(compare==0){
        if( v1->utxo_index > v2->utxo_index){
            return 1;
        }else if(v1->utxo_index < v2->utxo_index){
            return -1;
        }else{
            // Error: This is a double spend condition
            return 0;
        }
    }
    return compare;
}

int inputBufferCompareHelper(const void * i1, const void * i2){
    struct TransferableInputRecord * v1 = (struct TransferableInputRecord *)i1;
    struct TransferableInputRecord * v2 = (struct TransferableInputRecord *)i2;
    return inputBufferCompare(v1, v2);
}



uint8_t * avaxPackUInt32(uint32_t value, uint8_t * buffer)
{
    
    UInt32SetBE(buffer, value);
    return buffer ;
}

uint8_t * avaxPackUInt64(uint64_t value, uint8_t* buffer)
{
    UInt64SetBE(buffer, value);
    return buffer;
}

extern uint8_t * avaxPackByteArray(uint8_t * bytes, size_t len,uint8_t * buffer, int include_len_prefix){
    
    assert(bytes!=NULL);
    assert(buffer != NULL);
    size_t offset = 0;
    if(include_len_prefix){
        avaxPackUInt64((uint64_t)len, buffer);
        offset +=4;
    }
    memcpy(&buffer[offset], bytes, len);
    return buffer;
    
}

extern uint32_t avaxOutputTypeToInt32(output_type type){
    if(type == SECP256K1TransferOutput){
        return 0x07;
    }
    return 0;
};


int avaxPackTransferableOutput(struct TransferableOutputRecord output, uint8_t * out_buffer, size_t * output_size){
   
   
    uint32_t numAddresses =(uint32_t) array_count(output.output.secp256k1.addresses);
    uint32_t offset = 0;
    if(out_buffer==NULL){
        *output_size =32+4+8+8+4+4+numAddresses*AVAX_RMD_BYTES;
        return 1;
    }
    uint8_t buffer[32+4+8+8+4+4+numAddresses*AVAX_RMD_BYTES]; //bytes type_id+ amount+ locktime + threshold + addresses_len + addresses[20]...
    //TODO: can I use the enum directly for its value or will it break portability ? If mapping then use avaxOutputTypeToInt32
    UInt256Set(&buffer[offset], output.asset.id);
    offset+=32;
    UInt32SetBE(&buffer[offset],output.type_id);
    offset+=4;
    UInt64SetBE(&buffer[offset], output.output.secp256k1.amount);
    offset+=8;
    UInt64SetBE(&buffer[offset], output.output.secp256k1.locktime);
    offset+=8;
    UInt32SetBE(&buffer[offset], output.output.secp256k1.threshold);
    offset+=4;
    UInt32SetBE(&buffer[offset], numAddresses);
    offset+=4;
    for(uint32_t i =0; i < numAddresses; i++){
        memcpy(&buffer[offset],output.output.secp256k1.addresses[i].rmd160, AVAX_RMD_BYTES);
        offset+= (AVAX_RMD_BYTES);
    }
    printf("\r\nproduced following output buffer:\r\n");
    for(int i=0; i < 32+4+8+8+4+4+numAddresses*AVAX_RMD_BYTES; i++){
        printf("%02x", buffer[i]);
    }
    printf("\r\n");
    *output_size = offset;
    memcpy(out_buffer, &buffer[0], offset);
    return 1;
}

int avaxPackTransferableInput(struct TransferableInputRecord input, uint8_t * out_buffer, size_t * output_size){

    uint32_t numAddresses =(uint32_t) array_count(input.input.secp256k1.address_indices);
    uint32_t offset = 0;
    if(out_buffer==NULL){
        *output_size =32+4+32+4+8+4+numAddresses*4;
        return 1;
    }
    uint8_t buffer[32+4+32+4+8+4+numAddresses*4]; //bytes txid , output_idx + assetId +  type_id+ amount+ addresses_len + address_indices[4]...
    
    UInt256Set(&buffer[offset], input.tx.id);
    offset+=32;
    UInt32SetBE(&buffer[offset], input.utxo_index);
    offset+=4;
    UInt256Set(&buffer[offset], input.asset.id);
    offset+=32;
    UInt32SetBE(&buffer[offset],input.type_id);
    offset+=4;
    UInt64SetBE(&buffer[offset], input.input.secp256k1.amount);
    offset+=8;
    UInt32SetBE(&buffer[offset], numAddresses);
    offset+=4;
    for(uint32_t i =0; i < numAddresses; i++){
        UInt32SetBE(&buffer[offset],input.input.secp256k1.address_indices[i]);
        offset+= 4;
    }
    printf("\r\nproduced following input buffer:\r\n");
    for(int i=0; i < 32+4+32+4+8+4+numAddresses*4; i++){
        printf("%02x", buffer[i]);
    }
    printf("\r\n");
    *output_size = offset;
    memcpy(out_buffer, &buffer[0], offset);
    return 1;
}

extern int avaxPackBaseTx(struct BaseTxRecord baseTx, uint8_t * out_buffer, size_t * out_size){
    //const barr = [codec, txtype, this.networkid, this.blockchainid, this.numouts, all outs , numins, all ins, memolen, memo];
    size_t final_buffer_size=2+4+4+32+4+4+4+strlen(baseTx.memo);
    size_t bufferSize;
    size_t outputBuffersLen=0;
    size_t inputBuffersLen=0;
    
    for(int i=0; i < array_count(baseTx.outputs); i++){
        avaxPackTransferableOutput(baseTx.outputs[i],NULL,&bufferSize);
        outputBuffersLen+=bufferSize;
    }
    final_buffer_size+= outputBuffersLen;
    for(int i=0; i < array_count(baseTx.inputs); i++){
        avaxPackTransferableInput(baseTx.inputs[i],NULL,&bufferSize);
        inputBuffersLen+=bufferSize;
    }
    final_buffer_size+=inputBuffersLen;
    
    if(out_buffer==NULL){
        *out_size = final_buffer_size;
        return 1;
    }
    
    uint8_t buffer[final_buffer_size];
    uint32_t offset=0;
    UInt16SetBE(&buffer[offset], baseTx.codec);
    offset+=2;
    UInt32SetBE(&buffer[offset], baseTx.type_id);
    offset+=4;
    UInt32SetBE(&buffer[offset], baseTx.network_id);
    offset+=4;
    memcpy(&buffer[offset], baseTx.blockchain_id, 32);
    offset+=32;
    
    UInt32SetBE(&buffer[offset], (uint32_t)array_count(baseTx.outputs));
    offset+=4;
    
    BRArrayOf(struct OutputBuffer) buffers;
    array_new(buffers,2);
    for(int i=0; i < array_count(baseTx.outputs); i++ /*,offset+= bufferSize*/){
        struct OutputBuffer obuffer;
        avaxPackTransferableOutput(baseTx.outputs[i],NULL,&obuffer.len);
        obuffer.bytes = calloc(obuffer.len, sizeof(uint8_t));
        avaxPackTransferableOutput(baseTx.outputs[i],obuffer.bytes,&obuffer.len);
        array_add(buffers,obuffer);
    }
    
    mergesort_brd(buffers, array_count(buffers), sizeof(struct OutputBuffer), ouputBufferCompareHelper);
    for(int i=0; i < array_count(buffers); i++){
        memcpy(&buffer[offset], buffers[i].bytes, buffers[i].len);
        offset+=buffers[i].len;
//        for(int j=0; j < buffers[i].len; j++){
//            printf("%02X", buffers[i].bytes[j]);
//        }
    }
    freeOutputBuffers(buffers);
    array_clear(buffers);
    array_free(buffers);
    
   
    
    UInt32SetBE(&buffer[offset], (uint32_t)array_count(baseTx.inputs));
    offset+=4;
    //TODO: array_new(buffers,  (uint32_t)array_count(baseTx.inputs));
    mergesort_brd(baseTx.inputs, array_count(baseTx.inputs), sizeof(struct TransferableInputRecord), inputBufferCompareHelper);
    array_new(buffers,2);
    for(int i=0; i < array_count(baseTx.inputs); i++){
        struct OutputBuffer ibuffer;
        avaxPackTransferableInput(baseTx.inputs[i],NULL,&ibuffer.len);
        ibuffer.bytes = calloc(ibuffer.len , sizeof(uint8_t));
        avaxPackTransferableInput(baseTx.inputs[i],ibuffer.bytes,&ibuffer.len);
        array_add(buffers,ibuffer);
    }
    for(int i=0; i < array_count(buffers); i++){
        memcpy(&buffer[offset], buffers[i].bytes, buffers[i].len);
        offset+=buffers[i].len;
    }
    freeOutputBuffers(buffers);
    array_clear(buffers);
    array_free(buffers);
    
    
    UInt32SetBE(&buffer[offset],(uint32_t) strlen(baseTx.memo));
    offset+=4;
    memcpy(&buffer[offset],&baseTx.memo[0], strlen(baseTx.memo));
    offset+=strlen(baseTx.memo);
    assert(out_buffer!=NULL);
    memcpy(out_buffer, &buffer[0], offset);
    return 1;
}


extern int avaxPackSignatures(uint8_t * outbuffer,size_t * outbufferSize, BRArrayOf(struct BRAvaxCompactSignature) signatures){
    //[numsignatures [typeid==0x00000009 + numsignature + signature[65]]...
    *outbufferSize =4+array_count(signatures)* (4+4+AVAX_X_COMPACT_SIG_SIZE);
    
    if(outbuffer == NULL){
        return 1;
    }
    size_t offset = 0;
    UInt32SetBE(&outbuffer[offset],(uint32_t)array_count(signatures));
    offset+=4;
    for(int i=0; i < array_count(signatures); i++){
        //signature type id
        UInt32SetBE(&outbuffer[offset], (uint32_t)SECP256K1Credential);
        offset+=4;
        //NOTE: num creds: we only support Singleton Wallet
        UInt32SetBE(&outbuffer[offset], (uint32_t)0x1);
        offset+=4;
        memcpy(&outbuffer[offset], &signatures[i].bytes[0], AVAX_X_COMPACT_SIG_SIZE);
        offset+=AVAX_X_COMPACT_SIG_SIZE;
    }
    
    return 1;
}
