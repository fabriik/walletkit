package com.breadwallet.corenative.crypto;

import com.breadwallet.corenative.CryptoLibraryDirect;
import com.breadwallet.corenative.CryptoLibraryIndirect;
import com.breadwallet.corenative.utility.SizeT;
import com.google.common.primitives.UnsignedLong;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

import java.util.Map;

public class BRCryptoClientTransactionBundle extends PointerType {
    public static BRCryptoClientTransactionBundle create(
            BRCryptoTransferStateType status,
            byte[] transaction,
            UnsignedLong blockTimestamp,
            UnsignedLong blockHeight,
            Map<String, String> meta) {

        int metaCount = meta.size();
        String[] metaKeys = meta.keySet().toArray(new String[metaCount]);
        String[] metaVals = meta.values().toArray(new String[metaCount]);

        Pointer pointer = CryptoLibraryIndirect.cryptoClientTransactionBundleCreate(
                status.toCore(),
                transaction,
                new SizeT(transaction.length),
                blockTimestamp.longValue(),
                blockHeight.longValue(),
                new SizeT(metaCount),
                metaKeys,
                metaVals);

        return new BRCryptoClientTransactionBundle(pointer);
    }

    public void release () {
        CryptoLibraryDirect.cryptoClientTransactionBundleRelease(
                this.getPointer()
        );
    }

    public BRCryptoClientTransactionBundle() {
        super();
    }

    public BRCryptoClientTransactionBundle(Pointer address) {
        super(address);
    }
}
