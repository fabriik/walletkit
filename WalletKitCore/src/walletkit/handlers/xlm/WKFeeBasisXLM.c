//
//  WKFeeBasisXLM.c
//  WalletKitCore
//
//  Created by Carl Cherry on 2021-05-21.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#include "WKXLM.h"
#include "crypto/BRCryptoFeeBasisP.h"
#include "stellar/BRStellar.h"

static BRCryptoFeeBasisXLM
cryptoFeeBasisCoerce (BRCryptoFeeBasis feeBasis) {
    assert (CRYPTO_NETWORK_TYPE_XLM == feeBasis->type);
    return (BRCryptoFeeBasisXLM) feeBasis;
}

typedef struct {
    BRStellarFeeBasis xlmFeeBasis;
} BRCryptoFeeBasisCreateContextXLM;

static void
cryptoFeeBasisCreateCallbackXLM (BRCryptoFeeBasisCreateContext context,
                             BRCryptoFeeBasis feeBasis) {
    BRCryptoFeeBasisCreateContextXLM *contextXLM = (BRCryptoFeeBasisCreateContextXLM*) context;
    BRCryptoFeeBasisXLM feeBasisXLM = cryptoFeeBasisCoerce (feeBasis);
    
    feeBasisXLM->xlmFeeBasis = contextXLM->xlmFeeBasis;
}

private_extern BRCryptoFeeBasis
cryptoFeeBasisCreateAsXLM (BRCryptoUnit unit, BRStellarFee fee) {
    BRStellarFeeBasis xlmFeeBasis;
    xlmFeeBasis.costFactor = 1;
    xlmFeeBasis.pricePerCostFactor = fee;
    
    BRCryptoFeeBasisCreateContextXLM contextXLM = {
        xlmFeeBasis
    };
    
    return cryptoFeeBasisAllocAndInit (sizeof (struct BRCryptoFeeBasisXLMRecord),
                                       CRYPTO_NETWORK_TYPE_XLM,
                                       unit,
                                       &contextXLM,
                                       cryptoFeeBasisCreateCallbackXLM);
}

private_extern BRStellarFeeBasis
cryptoFeeBasisAsXLM (BRCryptoFeeBasis feeBasis) {
    BRCryptoFeeBasisXLM feeBasisXLM = cryptoFeeBasisCoerce (feeBasis);
    return feeBasisXLM->xlmFeeBasis;
}

static void
cryptoFeeBasisReleaseXLM (BRCryptoFeeBasis feeBasis) {
}

static double
cryptoFeeBasisGetCostFactorXLM (BRCryptoFeeBasis feeBasis) {
    return (double) cryptoFeeBasisCoerce (feeBasis)->xlmFeeBasis.costFactor;
}

static BRCryptoAmount
cryptoFeeBasisGetPricePerCostFactorXLM (BRCryptoFeeBasis feeBasis) {
    BRStellarFeeBasis xlmFeeBasis = cryptoFeeBasisCoerce (feeBasis)->xlmFeeBasis;
    return cryptoAmountCreateAsXLM (feeBasis->unit, CRYPTO_FALSE, xlmFeeBasis.pricePerCostFactor);
}

static BRCryptoAmount
cryptoFeeBasisGetFeeXLM (BRCryptoFeeBasis feeBasis) {
    return cryptoFeeBasisGetPricePerCostFactor (feeBasis);
}

static BRCryptoBoolean
cryptoFeeBasisIsEqualXLM (BRCryptoFeeBasis feeBasis1, BRCryptoFeeBasis feeBasis2) {
    BRCryptoFeeBasisXLM fb1 = cryptoFeeBasisCoerce (feeBasis1);
    BRCryptoFeeBasisXLM fb2 = cryptoFeeBasisCoerce (feeBasis2);

    return stellarFeeBasisIsEqual (&fb1->xlmFeeBasis, &fb2->xlmFeeBasis);
}

// MARK: - Handlers

BRCryptoFeeBasisHandlers cryptoFeeBasisHandlersXLM = {
    cryptoFeeBasisReleaseXLM,
    cryptoFeeBasisGetCostFactorXLM,
    cryptoFeeBasisGetPricePerCostFactorXLM,
    cryptoFeeBasisGetFeeXLM,
    cryptoFeeBasisIsEqualXLM
};
