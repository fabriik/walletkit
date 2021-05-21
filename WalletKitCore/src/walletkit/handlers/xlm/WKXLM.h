//
//  WKSTELLAR.h
//  WalletKitCore
//
//  Created by Carl Cherry on 2021-05-19.
//  Copyright © 2021 Breadwinner AG. All rights reserved.
//
//  See the LICENSE file at the project root for license information.
//  See the CONTRIBUTORS file at the project root for a list of contributors.
//
#ifndef WKSTELLAR_h
#define WKSTELLAR_h

#include "crypto/handlers/BRCryptoHandlersExport.h"
#include "crypto/BRCryptoFeeBasisP.h"

#include "stellar/BRStellar.h"

#ifdef __cplusplus
extern "C" {
#endif

// MARK: - Address

typedef struct BRCryptoAddressXLMRecord {
    struct BRCryptoAddressRecord base;
    BRStellarAddress addr;
} *BRCryptoAddressXLM;

extern BRCryptoAddress
cryptoAddressCreateAsXLM (BRStellarAddress addr);

extern BRCryptoAddress
cryptoAddressCreateFromStringAsXLM (const char *string);

private_extern BRStellarAddress
cryptoAddressAsXLM (BRCryptoAddress address);

// MARK: - Network

typedef struct BRCryptoNetworkXLMRecord {
    struct BRCryptoNetworkRecord base;
    // Nothing more needed
} *BRCryptoNetworkXLM;

// MARK: - Transfer

typedef struct BRCryptoTransferXLMRecord {
    struct BRCryptoTransferRecord base;

    BRStellarTransaction xlmTransaction;
} *BRCryptoTransferXLM;

extern BRCryptoTransferXLM
cryptoTransferCoerceXLM (BRCryptoTransfer transfer);

extern BRCryptoTransfer
cryptoTransferCreateAsXLM (BRCryptoTransferListener listener,
                           BRCryptoUnit unit,
                           BRCryptoUnit unitForFee,
                           BRCryptoTransferState state,
                           BRStellarAccount xlmAccount,
                           BRStellarTransaction xlmTransaction);

extern BRStellarTransaction
cryptoTransferAsXLM (BRCryptoTransfer transfer);

// MARK: - Wallet

typedef struct BRCryptoWalletXLMRecord {
    struct BRCryptoWalletRecord base;
    BRStellarAccount xlmAccount;
} *BRCryptoWalletXLM;

extern BRCryptoWalletHandlers cryptoWalletHandlersXLM;

private_extern BRCryptoWallet
cryptoWalletCreateAsXLM (BRCryptoWalletListener listener,
                         BRCryptoUnit unit,
                         BRCryptoUnit unitForFee,
                         BRStellarAccount xlmAccount);

private_extern BRCryptoHash
cryptoHashCreateAsXLM (BRStellarTransactionHash hash);

private_extern BRStellarTransactionHash
stellarHashCreateFromString (const char *string);

// MARK: - Wallet Manager

typedef struct BRCryptoWalletManagerXLMRecord {
    struct BRCryptoWalletManagerRecord base;
} *BRCryptoWalletManagerXLM;

extern BRCryptoWalletManagerHandlers cryptoWalletManagerHandlersXLM;

// MARK: - Fee Basis

typedef struct BRCryptoFeeBasisXLMRecord {
    struct BRCryptoFeeBasisRecord base;
    BRStellarFeeBasis xlmFeeBasis;
} *BRCryptoFeeBasisXLM;

private_extern BRCryptoFeeBasis
cryptoFeeBasisCreateAsXLM (BRCryptoUnit unit, BRStellarAmount fee);

private_extern BRStellarFeeBasis
cryptoFeeBasisAsXLM (BRCryptoFeeBasis feeBasis);

// MARK: - Support

#define FIELD_OPTION_DESTINATION_TAG        "DestinationTag"
#define FIELD_OPTION_INVOICE_ID             "InvoiceId"

private_extern int // 1 if equal, 0 if not.
stellarCompareFieldOption (const char *t1, const char *t2);

private_extern BRCryptoAmount
cryptoAmountCreateAsXLM (BRCryptoUnit unit, BRCryptoBoolean isNegative, BRStellarAmount value);

private_extern const char **
stellarAddressGetTransactionAttributeKeys (BRStellarAddress address, int asRequired, size_t *count);

#ifdef __cplusplus
}
#endif

#endif WKSTELLAR_h
