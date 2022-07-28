//
//  BRWOCParams.h
//  
//
//  Created by Christina Peterson on 7/26/22.
//

#ifndef BRWOCParams_h
#define BRWOCParams_h

#include "bitcoin/BRChainParams.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#define BSV_FORKID 0x40

extern const BRChainParams *BRWOCParams;
extern const BRChainParams *BRWOCTestNetParams;

static inline const BRChainParams *BRChainParamsGetWOC (int mainnet) {
    return mainnet ? BRWOCParams : BRWOCTestNetParams;
}

static inline int BRChainParamsIsWOC (const BRChainParams *params) {
    return BRWOCParams == params || BRWOCTestNetParams == params;
}

#ifdef __cplusplus
}
#endif

#endif /* BRWOCParams_h */
