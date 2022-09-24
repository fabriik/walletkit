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

extern void authorizerGetTokenId(char *str, long size, const char *script);

extern bool authorizerCheckAddress(const char *address, const char *script);

extern bool authorizerCheckSFP(const char *script);

extern unsigned long long authorizerGetAmount(const char *script_, long long walletId, const char *path_);

extern unsigned long long fileServiceGetAmount(const char *script_, long long walletId, const char *path_);

extern long long fileServiceLoadRPCGetWalletId(unsigned long index, const char *path_);

extern bool isTxidUnspentSFPToken (long long walletId, const char *txid_, const char *path);

extern bool fileServiceIsTxidUnspentSFPToken (const char *txid_, const char *fromAddress_, const char *path_);

extern void authorizerInitializeTables(const char *path_);

extern void initializeDeviceWallet(const char *mnemonic_, const char *path);

extern void getRUNAddressByDevice(char *addressHexStr, int addressSize, const char *path_);

extern void authorizerAddUtxo(const char *hex_, const char* path_);

extern void authorizerAddUtxoTest(const char* path_);

//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_);
//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_, const char *txid0, long long vout0, long long satoshis0, const char *script0, const char *address0, const char *path);
extern void authorizerCreateSerialization(long long index, char *authHexStr, int authHexSize, const char *path_);

extern void authorizerSaveTransfer(const char *txid_, const char *address_, unsigned long long amount_, unsigned long numTxns, const char *fromAddress_, const char *path_);

extern void authorizerSaveTransferWOC(const char *txid_, const char *address_, unsigned long long amount_, const char * mintId_, const char * fromAddress_, unsigned long numTxns, const char * jigId, const char *path_);

extern void authorizerGetTransferDataRUN(long long index, char *txnIdHexStr, int txnIdSize, char *addressHexStr, int addressSize, char *mintIdHexStr, int mintIdSize, char *fromAddressHexStr, int fromAddressSize, long long *amount, char *jigIdHexStr, int jigIdSize, const char *path_);

extern void fileServiceGetTransferDataRUN(long long index, char *txnIdHexStr, int txnIdSize, const char *path_);

extern void fileServiceGetTransferData(long long index, char *txnIdHexStr, int txnIdSize, char *fromAddressHexStr, int fromAddressSize, const char *path_);

extern void authorizerGetNumTxnsForTransfer(long long *numTxns, const char *path_);

extern void fileServiceGetNumTxnsForTransfer(long long *numTxns, const char *path_);

extern void authorizerGetNumTxnsForTransferRUN(long long *numTxns, const char *path_);

extern void fileServiceGetNumTxnsForTransferRUN(long long *numTxns, const char *path_);

extern void authorizerGetPrivKeyRun(const char * address_, char *privkeyHexStr, int privkeySize, const char *path_);

extern void authorizerGetPrivKeyDevice(char *privkeyHexStr, int privkeySize, const char *path_);

extern long long getWalletIdByPrimaryAddress(const char *address_, const char *path);

extern void getRUNAddressByWalletId(long long walletId, char *addressHexStr, int addressSize, const char *path_);

extern void authorizerSaveBundleRPC(const char *txHash, unsigned int version, unsigned long inCount, unsigned long outCount, unsigned int lockTime, unsigned int blockHeight, unsigned int timestamp, unsigned long long receiveAmount, const char *type, const char *mintId, const char *fromAddress, const char *senderAddress, unsigned int fingerPrint, const char *path_);

extern void authorizerSaveBundleInputRPC(int inCount, const char *txHash, const char *inputTxHash, const char *inputScript, const char *inputSignature, long long inputSequence, const char *path_);

extern void authorizerSaveBundleOutputRPC(int outCount, const char *txHash, unsigned long long outputAmount, const char *outputScript, const char *path_);

extern void initializePersistRPC(const char* path_);

extern unsigned long fileServiceLoadRPCGetSize(const char *path_);

extern char* fileServiceLoadRPCGetTxHash(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetFingerPrint(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetVersion(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetInCount(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetOutCount(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetLockTime(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetBlockHeight(unsigned long index, const char *path_);

extern long long fileServiceLoadRPCGetTimestamp(unsigned long index, const char *path_);

extern char* fileServiceLoadRPCGetType(unsigned long index, const char *path_);

extern unsigned long long fileServiceLoadRPCGetReceiveAmount(unsigned long index, const char *path_);

extern char* fileServiceLoadRPCGetMintId(unsigned long index, const char *path_);

extern char* fileServiceLoadRPCGetReceiverAdddress(unsigned long index, const char *path_);

extern char* fileServiceLoadRPCGetSenderAdddress(unsigned long index, const char *path_);

extern char* fileServiceLoadRPCGetInputTxHash(unsigned long index, const char *txHash, const char *path_);

extern char* fileServiceLoadRPCGetInputScript(unsigned long index, const char *txHash, const char *path_);

extern char* fileServiceLoadRPCGetInputSignature(unsigned long index, const char *txHash, const char *path_);

extern long long fileServiceLoadRPCGetInputSequence(unsigned long index, const char *txHash, const char *path_);

extern long long fileServiceLoadRPCGetOutputAmount(unsigned long index, const char *txHash, const char *path_);

extern char* fileServiceLoadRPCGetScript(const char *txHash, long long walletId, const char *path_);

extern char* fileServiceLoadRPCGetOutputScript(unsigned long index, const char *txHash, const char *path_);

#endif /* Header_h */
