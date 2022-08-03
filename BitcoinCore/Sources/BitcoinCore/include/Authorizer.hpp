//
//  Header.h
//  
//
//  Created by Christina Peterson on 6/13/22.
//

#ifndef Authorizer_h
#define Authorizer_h

#include <stdbool.h>

extern void authorizerGetAddress(char *str, long size, const char *script);

extern bool authorizerCheckAddress(const char *address, const char *script);

extern bool authorizerCheckSFP(const char *script);

extern unsigned long long authorizerGetAmount(const char *script);

extern bool isTxidUnspentSFPToken (long long walletId, const char *txid, const char *path);

extern void authorizerInitializeTables(const char *path_);

extern void authorizerAddUtxo(const char *hex_, const char* path_);

extern void authorizerAddUtxoTest(const char* path_);

//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_);
//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_, const char *txid0, long long vout0, long long satoshis0, const char *script0, const char *address0, const char *path);
extern void authorizerCreateSerialization(char *authHexStr, int authHexSize, const char *path_);

extern void authorizerSaveTransfer(const char *txid_, const char *address_, unsigned long long amount_, const char *path_);

extern void authorizerSaveTransferWOC(const char *txid_, const char *address_, unsigned long long amount_, const char * mintId_, const char * fromAddress_, unsigned long numTxns, const char *path_);

extern void authorizerGetTransferDataRun(long long index, char *txnIdHexStr, int txnIdSize, char *addressHexStr, int addressSize, char *mintIdHexStr, int mintIdSize, char *fromAddressHexStr, int fromAddressSize, long long *amount, const char *path_);

extern void authorizerGetNumTxnsForTransferRUN(long long *numTxns, const char *path_);

extern void authorizerGetPrivKeyRun(const char * address_, char *privkeyHexStr, int privkeySize, const char *path_);

extern long long getWalletIdByPrimaryAddress(const char *address_, const char *path);

extern void getRUNAddressByWalletId(long long walletId, char *addressHexStr, int addressSize, const char *path_);

extern void authorizerSaveBundleRPC(const char *txHash, unsigned int version, unsigned long inCount, unsigned long outCount, unsigned int lockTime, unsigned int blockHeight, unsigned int timestamp, unsigned long long receiveAmount, const char *mintId, const char *fromAddress, const char *senderAddress, const char *path_);

extern void authorizerSaveBundleInputRPC(unsigned long index, const char *txHash, const char *inputTxHash, const char *inputScript, unsigned long intputScriptLen, const char *inputSignature, unsigned long inputSigLength, long long inputSequence, const char *path_);

extern void authorizerSaveBundleOutputRPC(unsigned long index, const char *txHash, unsigned long long outputAmount, const char *outputScript, unsigned long outputScriptLength, const char *path_);

#endif /* Header_h */
