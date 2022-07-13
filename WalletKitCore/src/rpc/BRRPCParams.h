//
//  BRRPCParams.h
//
//
//  Created by Christina Peterson on 7/12/22.
//

#ifndef BRRPCParams_h
#define BRRPCParams_h

#include "bitcoin/BRChainParams.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define BSV_FORKID 0x40

extern const BRChainParams *BRRPCParams;
extern const BRChainParams *BRRPCTestNetParams;

static inline const BRChainParams *BRChainParamsGetRPC (int mainnet) {
    return mainnet ? BRRPCParams : BRRPCTestNetParams;
}

static inline int BRChainParamsIsRPC (const BRChainParams *params) {
    return BRRPCParams == params || BRRPCTestNetParams == params;
}

#ifdef __cplusplus
}
#endif

#endif /* BRRPCParams_h */
