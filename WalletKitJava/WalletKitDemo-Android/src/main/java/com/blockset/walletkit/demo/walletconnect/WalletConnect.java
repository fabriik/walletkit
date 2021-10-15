package com.blockset.walletkit.demo.walletconnect;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.blockset.walletkit.WalletConnector.Key;
import com.blockset.walletkit.WalletConnector;
import com.blockset.walletkit.brd.systemclient.ObjectCoder;
import com.blockset.walletkit.demo.DemoApplication;
import com.blockset.walletkit.demo.walletconnect.msg.EncryptedPayload;
import com.blockset.walletkit.demo.walletconnect.msg.JsonRpcError;
import com.blockset.walletkit.demo.walletconnect.msg.JsonRpcErrorResponse;
import com.blockset.walletkit.demo.walletconnect.msg.JsonRpcRequest;
import com.blockset.walletkit.demo.walletconnect.msg.JsonRpcResponse;
import com.blockset.walletkit.demo.walletconnect.msg.PeerMeta;
import com.blockset.walletkit.demo.walletconnect.msg.SocketMessage;
import com.blockset.walletkit.demo.walletconnect.msg.WCSessionRequestReq;
import com.blockset.walletkit.demo.walletconnect.msg.WCSessionRequestResp;
import com.blockset.walletkit.demo.walletconnect.msg.WCSessionUpdateReq;
import com.blockset.walletkit.errors.WalletConnectorError;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;


import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class WalletConnect {

    private static final Logger Log = Logger.getLogger(DemoApplication.class.getName());
    private static final int RFC_6455_SECTION_7_DOT_4__NORMAL_CLOSURE = 1000;

    private final OkHttpClient      client = new OkHttpClient();
    private final ObjectCoder       coder = ObjectCoder.createObjectCoderWithFailOnUnknownProperties();
    private final int               chainId;
    private WebSocket               socket;
    private WalletConnectSession    session;
    private WalletConnector         connector;
    private Key                     key;

    private String hexEncode(byte[] binary) {
        StringBuilder build = new StringBuilder();
        build.append("0x");
        for (byte b: binary) {
            build.append(String.format("%02x", b));
        }
        return build.toString();
    }

    private int fromHex(char c) {
        if (c >= '0' && c <= '9')
            return c - 48;
        if (c >= 'a' && c <= 'f')
            return c - 97 + 10;
        if (c >= 'A' && c <= 'F')
            return c - 65 + 10;
        throw new IllegalArgumentException("Invalid char in hex decode: " + c);
    }
    private byte[] hexDecode(String s) {
        if (s.startsWith("0x"))
            s = s.substring(2);

        if (s.length() % 2 != 0)
            throw new IllegalArgumentException("Bad hex string input: " + s);

        byte[] b = null;
        try {
            int pos = 0;
            b = new byte[s.length() / 2];
            while (pos < s.length()) {
                b[pos/2] = (byte)((fromHex(s.charAt(pos)) << 4 | fromHex(s.charAt(pos+1))) & 0xff);
                pos += 2;
            }
        } catch(IllegalArgumentException ie) {
            throw new IllegalArgumentException("Bad hex string: " + s + "(" + ie.toString() + ")");
        }
        return b;
    }

    // public enum WalletConnectError {

        // Unable to establish connection to bridge
   //     WALLET_CONNECT_CONNECTION_ERROR
  //  }

    public interface SessionApprover {
        void accept(List<String> accounts,
                    String   url,
                    String   name,
                    String   description,
                    List<String> icons);
        void reject();
    }

    public interface RequestApprover {
        void approve();
        void reject();
    }

    public interface DAppSessionClient {

        enum ApprovalType {
            APPROVAL_FOR_TYPED_DATA("Approval to sign 'Typed Data'"),
            APPROVAL_FOR_OPAQUE_DATA("Approval to sign data"),
            APPROVAL_FOR_SENDING_TRANSACTION("Approval to sign and submit transaction");

            private String description;

            ApprovalType(String desc) { description = desc; }

            @NonNull
            @Override
            public String toString() {
                return description;
            }
        };

        void sessionStarted (   String          dApp,
                                String          topic,
                                String          clientId,
                                String          peerId  );
        void sessionError   (   String          reason  );

        void grantSession   (   String          bridgeUrl,
                                String          dAppName,
                                String          description,
                                String[]        icons,
                                SessionApprover userApproval    );

        void approveRequest(    Number              requestId,
                                ApprovalType        requestType,
                                Map<String, String> requestData,
                                RequestApprover     requestApproval );

    };

    // As per WalletConnect 1.0 'kotlin-walletconnect-lib' example
    private static final class EncryptedPayloadHandler {

        static String recover(String key, EncryptedPayload payload) {
            PKCS7Padding pkcs7Padding = new PKCS7Padding();

            // TODO verify hmac

            // Decrypt
            CBCBlockCipher cipher = new CBCBlockCipher(new AESEngine());
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(cipher, pkcs7Padding);
            ParametersWithIV ivAndKey = new ParametersWithIV(new KeyParameter(decode(key)),
                                                             decode(payload.getIv()));
            aes.init(false, ivAndKey);
            byte[] encryptedData = decode(payload.getData());
            byte[] decryptedData = new byte[encryptedData.length];
            int len = aes.processBytes(encryptedData, 0, encryptedData.length, decryptedData, 0);
            try {
                len += aes.doFinal(decryptedData, len);
            } catch(InvalidCipherTextException e) {
                Log.log(Level.SEVERE, "Failed decrypt message: " + e.toString());
            }

            return new String(decryptedData, 0, len);
        }

        static EncryptedPayload construct(String key, String data) {

            byte[] dataBytes = data.getBytes();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            PKCS7Padding pkcs7Padding = new PKCS7Padding();
            CBCBlockCipher cipher = new CBCBlockCipher(new AESEngine());
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(cipher, pkcs7Padding);
            ParametersWithIV ivAndKey = new ParametersWithIV(new KeyParameter(decode(key)), iv);
            aes.init(true, ivAndKey);
            int minSize = aes.getOutputSize(dataBytes.length);
            byte[] encryptedData = new byte[minSize];
            int lengthWoPad = aes.processBytes(dataBytes,
                                               0,
                                               dataBytes.length,
                                               encryptedData,
                                               0);
            try {
                aes.doFinal(encryptedData, lengthWoPad);
            } catch (DataLengthException dle) {
                Log.log(Level.SEVERE, "Length of encrypted buffer is insufficient: " + dle);
                return null;
            } catch (InvalidCipherTextException icte) {
                Log.log(Level.SEVERE, "Padding is expected and not found: " + icte);
                return null;
            }

            // Keyed hash message authentication code using SHA256 hashing
            HMac hmac = new HMac(new SHA256Digest());
            hmac.init(new KeyParameter(decode(key)));
            byte[] hmacValue = new byte[hmac.getMacSize()];
            hmac.update(encryptedData, 0, encryptedData.length);
            hmac.update(iv, 0, iv.length);
            hmac.doFinal(hmacValue, 0);

            return EncryptedPayload.create(encode(encryptedData),
                                           encode(hmacValue),
                                           encode(iv));
        }

        static String encode(byte[] binary) {
            StringBuilder b = new StringBuilder();
            for (byte value : binary) {
                b.append(Integer.toHexString((value & 0xf0) >> 4));
                b.append(Integer.toHexString((value & 0x0f)));
            }
            return b.toString();
        }

        static int hexToBin(char c) {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return c - 'a' + 10;
        }

        static byte[] decode(String binHex) {
            if ((binHex.length() % 2) != 0)
                throw new IllegalArgumentException("Invalid data input length (not even): " + binHex);

            if (binHex.startsWith("0x"))
                binHex = binHex.substring(2);

            byte[] b = new byte[binHex.length() / 2];
            int i = 0;
            while (i < binHex.length()) {
                b[i / 2] = (byte)(((hexToBin(binHex.charAt(i)) << 4) & 0xf0 ) | hexToBin(binHex.charAt(i + 1)));
                i += 2;
            }
            return b;
        }
    }

    public final class WalletConnectSession extends WebSocketListener {

        private final WalletConnectSessionDescription sessionInfo;
        private final DAppSessionClient               sessionClient;
        private final ExecutorService                 onUserExecutor;
        private final int                             chainId;

        // UUIDs for bridge session, this client and the connected peer
        private final String                          clientId;
        private String                                peerId;

        // See @WalletConnect/json-rpc-utils/dis/esm/format.js
        private Number payloadId() {
            double date = (new Date().getTime()) * Math.pow(10, 3);
            double extra = Math.floor(Math.random() * Math.pow(10, 3));
            return Long.valueOf(Double.valueOf(date + extra).longValue());
        }

        private WalletConnectSession(
                int                             chainId,
                WalletConnectSessionDescription sessionInfo,
                DAppSessionClient               sessionClient) {

            this.chainId = chainId;
            this.sessionInfo = sessionInfo;
            this.sessionClient = sessionClient;

            onUserExecutor = Executors.newCachedThreadPool();
            clientId = UUID.randomUUID().toString();
        }

        public void disconnect(WebSocket webSocket) {

            // First send session update indicating session is closed OK.

            // WalletConnect 1.0 sample wallet sends null for accounts, chainId and networkId
            // in the wc_sessionUpdate method params. Well networkId is not described in the
            // 'Session Update' section of the spec, but its added here to be adherent to the
            // example
            WCSessionUpdateReq update = WCSessionUpdateReq.create(
                    false,
                    null,
                    null,
                    null);
            try {
                String updateJson = coder.serializeObject(update);
                JsonRpcRequest updateRequest = JsonRpcRequest.create(
                        payloadId(),
                        JsonRpcRequest.WALLET_CONNECT_1_0_RPC_VERSION,
                        "wc_sessionUpdate",
                        Collections.singletonList(updateJson));
                String jsonRpcJson = coder.serializeObject(updateRequest);
                EncryptedPayload payload = EncryptedPayloadHandler.construct(
                        this.sessionInfo.getDAppPubKey(),
                        jsonRpcJson);
                String payloadJson = coder.serializeObject(payload);
                SocketMessage response = SocketMessage.create(this.peerId,
                        SocketMessage.PUBLISH_TYPE,
                        payloadJson,
                        true  );
                String responseJson = coder.serializeObject(response);
                webSocket.send(responseJson);
            } catch(ObjectCoder.ObjectCoderException e) {
                Log.log(Level.SEVERE, "WC: Cannot serialize wc_sessionResponse: " + e);
            }

            webSocket.close(RFC_6455_SECTION_7_DOT_4__NORMAL_CLOSURE, null);
            Log.log(Level.FINE, "WC: session closed");
        }
        private void subscribeTo(WebSocket webSocket, String topic) {

            // Immediately on open subscribe for interest. Sample dApp indicates
            // silent = true
            SocketMessage subs = SocketMessage.create(topic,
                    SocketMessage.SUBSCRIBE_TYPE,
                    SocketMessage.NO_PAYLOAD,
                    true);
            try {
                String jsonRpc = coder.serializeObject(subs);
                webSocket.send(jsonRpc);
            } catch(ObjectCoder.ObjectCoderException badJsonEncode) {
                Log.log(Level.SEVERE, "WC: Failed serialization bridge message: " + badJsonEncode);
            }
        }

        @Override
        public void onClosed(WebSocket webSocket, int code, String reason) {
            super.onClosed(webSocket, code, reason);

            Log.log(Level.FINE, "WC: websocket closed (" + code + "): " + reason);
        }

        @Override
        public void onOpen(@NonNull WebSocket webSocket, @NonNull Response response) {
            super.onOpen(webSocket, response);
            Log.log(Level.FINE, String.format("WC: Connected, subscribe to %s for topic %s",
                                              sessionInfo.getBridge(),
                                              sessionInfo.getTopic()));

            subscribeTo(webSocket, sessionInfo.getTopic());
        }

        @Override
        public void onFailure(@NonNull WebSocket webSocket, @NonNull Throwable t, @Nullable Response response) {
            super.onFailure(webSocket, t, response);
            Log.log(Level.SEVERE, "WC: Failed on connection " + sessionInfo.toString() + " with " + t);
        }

        @Override
        public void onMessage(@NonNull WebSocket webSocket, @NonNull String text) {
            super.onMessage(webSocket, text);
            Log.log(Level.FINE, "WC: " +
                    "Received " + text);

            String failureReason = "NA";
            try {
                // Decode the general socket message
                failureReason = "deserialize socket message";
                SocketMessage msg = coder.deserializeJson(SocketMessage.class, text);
                Log.log(Level.FINE, "WC: RCV MSG:\n" + msg.toString());

                // Decode the encrypted payload
                failureReason = "deserialize encrypted payload";
                EncryptedPayload payload = coder.deserializeJson(EncryptedPayload.class, msg.getPayload());
                Log.log(Level.FINE, "WC:    payload: " + payload.toString());

                String content = EncryptedPayloadHandler.recover(sessionInfo.getDAppPubKey(),
                                                                 payload);
                Log.log(Level.FINE, "WC: Decrypted message: " + content);

                // The general message envelope can be extracted and will contain the specific method...
                failureReason = "deserialize actual payload";
                JsonRpcRequest rpc = coder.deserializeJson(JsonRpcRequest.class, content);

                if (!rpc.getMethod().isPresent()) {
                    Log.log(Level.WARNING, "JsonRpc method w/o a method? " + content);
                    return;
                }

                // TODO.. handle wc_sessionUpdate to handle close from far end

                switch (rpc.getMethod().get()) {
                    case "wc_sessionRequest":
                        failureReason = "handle wc_sessionRequest";

                        // At the moment, only expect one child of the session request.
                        if (rpc.getParams().size() > 1)
                            throw new IllegalArgumentException("Unexpected WalletConnect json rpc message contains > 1 params: " + content);

                        handleSessionRequest(rpc, webSocket);
                        break;

                    case "eth_signTypedData":
                        failureReason = "handle eth_signTypedData";

                        handleSignTypedData(rpc.getId(),
                                            DAppSessionClient.ApprovalType.APPROVAL_FOR_TYPED_DATA,
                                            rpc.getParams(),
                                            webSocket);

                        break;

                    case "eth_sign":

                        handleSignData(rpc.getId(),
                                       DAppSessionClient.ApprovalType.APPROVAL_FOR_OPAQUE_DATA,
                                       rpc.getParams(),
                                       webSocket);
                        break;

                    case "eth_sendTransaction":

                        handleSendTransaction(rpc.getId(),
                                              DAppSessionClient.ApprovalType.APPROVAL_FOR_SENDING_TRANSACTION,
                                              rpc.getParams(),
                                              webSocket);
                        break;

                    default:
                        Log.log(Level.FINE, "Unhandled WalletConnect message: " + rpc.getMethod().get());
                        break;
                }
            } catch(ObjectCoder.ObjectCoderException badJsonDecode) {
                Log.log(Level.SEVERE, "WC: Failed deserialization of bridge message on"
                        + failureReason + " with: " + badJsonDecode);
            } catch(Exception e) {
                Log.log(Level.SEVERE, "WC: EXCEPTION " + e);
            }
        }

        private void handleSessionRequest(JsonRpcRequest rpc, WebSocket webSocket) throws ObjectCoder.ObjectCoderException {

            WCSessionRequestReq sessionRequest = coder.deserializeJson(WCSessionRequestReq.class, rpc.getParams().get(0));
            // We accept this session request with this peer id as
            // dApp is subscribed on bridge for messages to it.
            this.peerId = sessionRequest.getPeerId();

            onUserExecutor.submit(() -> sessionClient.grantSession(
                    sessionRequest.getPeerMeta().getUrl(),
                    sessionRequest.getPeerMeta().getName(),
                    sessionRequest.getPeerMeta().getDescription(),
                    sessionRequest.getPeerMeta().getIcons(),
                    new SessionApprover() {
                        @Override
                        public void accept(
                                List<String> accounts,
                                String   url,
                                String   name,
                                String   description,
                                List<String> iconsList ) {

                            String[] icons = new String[0];
                            PeerMeta aboutMe = PeerMeta.create(description,
                                    url,
                                    iconsList.toArray(icons),
                                    name);

                            sessionAccept(webSocket,
                                    rpc.getId(),
                                    peerId,
                                    aboutMe,
                                    accounts);

                            // Now must register a subscribe on bridge for our peerId/clientId
                            // which will become the topic to which dApp sends its requests
                            subscribeTo(webSocket, clientId);

                            // UI, session is started..
                            onUserExecutor.submit(() -> sessionClient.sessionStarted(sessionRequest.getPeerMeta().getName(),
                                    sessionInfo.getTopic(),
                                    peerId,
                                    clientId));
                        }

                        @Override
                        public void reject() {
                            sessionReject(webSocket,
                                          rpc.getId());
                        }
                    }
                )
            );
        }

        private void handleSignTypedData(
                Number                          rpcId,
                DAppSessionClient.ApprovalType  toApproveOf,
                List<String>                    params,
                WebSocket                       webSocket) {

            // Essentially, metadata of the request for UI to show it
            Map<String, String> requestElements = new HashMap<String, String>();
            requestElements.put("address", params.get(0));
            requestElements.put("typedData", params.get(1));

            onUserExecutor.submit(() -> sessionClient.approveRequest(
                    rpcId,
                    toApproveOf,
                    requestElements,
                    new RequestApprover() {

                        @Override
                        public void approve() {

                            WalletConnector.Result<WalletConnector.DigestAndSignaturePair, WalletConnectorError> res =
                                connector.sign(params.get(1), key);

                            if (res.isSuccess()) {
                                String sigValue = hexEncode(res.getSuccess().signature.getData());
                                sendResponse(webSocket, rpcId, peerId, sigValue);

                                Log.log(Level.FINE, String.format("WC: eth_signTypedData msg %s", params.get(1)));
                                Log.log(Level.FINE, String.format("WC:     digest: %s", hexEncode(res.getSuccess().digest.getData32())));
                                Log.log(Level.FINE, String.format("WC:     signature: %s", sigValue));
                            } else {
                                sendError(JsonRpcError.SERVER_ERROR,
                                        "Failed data signing of typed data",
                                        webSocket,
                                        rpcId);
                            }
                        }

                        @Override
                        public void reject() {
                            sendError(JsonRpcError.SERVER_ERROR,
                                      "Failed or Rejected Request",
                                       webSocket,
                                       rpcId);
                        }
                    }
                    )
            );
        }

        private void handleSignData(
                Number                          rpcId,
                DAppSessionClient.ApprovalType  toApproveOf,
                List<String>                    params,
                WebSocket                       webSocket) {

            // Metadata for UI to show
            Map<String, String> requestElements = new HashMap<String, String>();
            requestElements.put("address", params.get(0));
            requestElements.put("message", params.get(1));

            onUserExecutor.submit(() -> sessionClient.approveRequest(
                    rpcId,
                    toApproveOf,
                    requestElements,
                    new RequestApprover() {

                        @Override
                        public void approve() {

                            WalletConnector.Result<WalletConnector.DigestAndSignaturePair, WalletConnectorError> res;

                            byte[] toSign = hexDecode(params.get(1));
                            res = connector.sign(toSign, key, true);
                            if (res.isSuccess()) {
                                String sigValue = hexEncode(res.getSuccess().signature.getData());
                                sendResponse(webSocket, rpcId, peerId, sigValue);

                                Log.log(Level.FINE, String.format("WC: eth_sign msg %s", params.get(1)));
                                Log.log(Level.FINE, String.format("WC:     message: %s", new String(toSign)));
                                Log.log(Level.FINE, String.format("WC:     digest: %s", hexEncode(res.getSuccess().digest.getData32())));
                                Log.log(Level.FINE, String.format("WC:     signature: %s", sigValue));
                            } else {
                                sendError(JsonRpcError.SERVER_ERROR,
                                        "Failed data signing",
                                        webSocket,
                                        rpcId);
                            }
                        }

                        @Override
                        public void reject() {
                            sendError(JsonRpcError.SERVER_ERROR,
                                      "Failed or RejectedRequest",
                                      webSocket,
                                      rpcId);
                        }
                    }
                    )
            );
        }

        private void handleSendTransaction(
                Number                          rpcId,
                DAppSessionClient.ApprovalType  toApproveOf,
                List<String>                    params,
                WebSocket                       webSocket) {

            // Metadata for UI to show
            Map<String, String> requestElements = new HashMap<String, String>();
            requestElements.put("transaction", params.get(0));

            onUserExecutor.submit(() -> sessionClient.approveRequest(
                    rpcId,
                    toApproveOf,
                    requestElements,
                    new RequestApprover() {

                        @Override
                        public void approve() {

                            // Use WalletKit WalletConnector to do the submission here...

                            // WalletConnect 1.0 sample transaction hash result:
                            String takenFromSampleWalletTransactionHash = "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331";
                            sendResponse(webSocket, rpcId, peerId, takenFromSampleWalletTransactionHash);
                        }

                        @Override
                        public void reject() {
                            sendError(JsonRpcError.SERVER_ERROR,
                                      "Failed or RejectedRequest",
                                      webSocket,
                                      rpcId);
                        }
                    }
                    )
            );
        }

        private void sessionAccept(
                WebSocket   sock,
                Number      rpcId,
                String      peerId,
                PeerMeta    peerMeta,
                List<String>    accountsList    ) {

            String[] accounts = new String[0];
            WCSessionRequestResp resp = WCSessionRequestResp.create(
                    clientId,
                    peerMeta,
                    true,
                    this.chainId,
                    accountsList.toArray(accounts));
            try {
                String respJson = coder.serializeObject(resp);
                sendResponse(sock, rpcId, peerId, respJson);
            } catch(ObjectCoder.ObjectCoderException e) {
                Log.log(Level.SEVERE, "WC: Cannot serialize wc_sessionResponse: " + e);
            }
        }

        // Session rejection is handled by returning an error message, not a
        // a wc_sessionResponse with an 'approved'=false as might be surmised by
        // what is given in the spec ("The sc_sessionRequest will expect a response
        // with the following parameters:"  ... details interface WCSessionRequestResponse...)
        private void sessionReject(
                WebSocket   sock,
                Number      rpcId) {

            // What the sample wallet does...
            JsonRpcError err = JsonRpcError.create(JsonRpcError.SERVER_ERROR, "Session Rejected");
            try {
                String errJson = coder.serializeObject(err);
                JsonRpcResponse jsonResp = JsonRpcResponse.create(
                        rpcId,
                        JsonRpcRequest.WALLET_CONNECT_1_0_RPC_VERSION,
                        errJson);
                String jsonRpcJson = coder.serializeObject(jsonResp);
                EncryptedPayload payload = EncryptedPayloadHandler.construct(this.sessionInfo.getDAppPubKey(),
                                                                             jsonRpcJson);
                String payloadJson = coder.serializeObject(payload);
                SocketMessage response = SocketMessage.create(
                        peerId,
                        SocketMessage.PUBLISH_TYPE,
                        payloadJson,
                        true  );
                String responseJson = coder.serializeObject(response);
                sock.send(responseJson);
            } catch(ObjectCoder.ObjectCoderException e) {
                Log.log(Level.SEVERE, "WC: Cannot serialize session rejection: " + e);
            }
        }

        private void sendError(
                int         errCode,
                String      msg,
                WebSocket   webSocket,
                Number      rpcId) {

            // Construct the error response as the WalletConnect 1.0 sample does.
            JsonRpcError rejectRequest = JsonRpcError.create(errCode, msg);
            try {
                String respJson = coder.serializeObject(rejectRequest);
                sendResponse(webSocket, rpcId, peerId, respJson);
            } catch (ObjectCoder.ObjectCoderException oce) {
                Log.log(Level.SEVERE, "WC: Failure encoding approval rejection " + oce);
            }
        }

        private void sendResponse(
                WebSocket   sock,
                Number      rpcId,
                String      peerId,
                String      responseResult) {

            try {
                JsonRpcResponse jsonResp = JsonRpcResponse.create(
                        rpcId,
                        JsonRpcRequest.WALLET_CONNECT_1_0_RPC_VERSION,
                        responseResult);
                String jsonRpcJson = coder.serializeObject(jsonResp);
                EncryptedPayload payload = EncryptedPayloadHandler.construct(this.sessionInfo.getDAppPubKey(),
                        jsonRpcJson);
                String payloadJson = coder.serializeObject(payload);
                SocketMessage response = SocketMessage.create(peerId,
                        SocketMessage.PUBLISH_TYPE,
                        payloadJson,
                        true  );
                String responseJson = coder.serializeObject(response);
                sock.send(responseJson);
            } catch(ObjectCoder.ObjectCoderException e) {
                Log.log(Level.SEVERE, "WC: Cannot send rpcId " + rpcId + ": " + e);
            }
        }

    }

    // Public constructor for now
    public WalletConnect(
        boolean             isMainnet,
        WalletConnector     connector,
        byte[]              paperKey) {

        // WalletConnect 1.0 is strictly an Ethereum thing, so we assign the
        // chain id based on mainnet vs testnet
        this.chainId = isMainnet ? 1 : 3;
        this.connector = connector;

        WalletConnector.Result<WalletConnector.Key, WalletConnectorError> result = connector.createKey(new String(paperKey));
        if (result.isSuccess()) {
            this.key = result.getSuccess();
        } else {
            throw new IllegalArgumentException("Unable to create signing key: " + result.getFailure().toString());
        }
    }

    public void connect(
        WalletConnectSessionDescription sessionRequest,
        DAppSessionClient               sessionListener    ) {

        this.session = new WalletConnectSession(this.chainId,
                                                sessionRequest,
                                                sessionListener);
        String wsUri = sessionRequest.getBridge().replace("https://", "wss://").replace("http://", "ws://");
        this.socket = client.newWebSocket(new Request.Builder().url(wsUri).build(), this.session);
    }

    public void disconnect() {
        this.session.disconnect(this.socket);
    }

}
