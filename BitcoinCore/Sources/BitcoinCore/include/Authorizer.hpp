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

//extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_);
extern void authorizerCreateSerialization(const char *toAddress, const char *fromAddress, const char *txid, long long vout, long long satoshis, const char *script_, const char *txid0, long long vout0, long long satoshis0, const char *script0, const char *address0, const char *path);

#endif /* Header_h */
