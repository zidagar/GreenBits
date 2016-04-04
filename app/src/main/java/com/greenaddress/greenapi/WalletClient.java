package com.greenaddress.greenapi;

import android.util.Base64;
import android.util.Log;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.util.concurrent.AsyncFunction;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.SettableFuture;
import com.greenaddress.greenbits.ui.BuildConfig;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;

import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoin.RewindResult;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VersionedChecksummedBytes;
import org.bitcoinj.core.WrongNetworkException;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.PBKDF2SHA512;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptChunk;
import org.codehaus.jackson.map.MappingJsonFactory;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.tavendo.autobahn.Wamp;
import de.tavendo.autobahn.WampConnection;
import de.tavendo.autobahn.WampOptions;
import de.tavendo.autobahn.secure.WebSocket;
import de.tavendo.autobahn.secure.WebSocketMessage;

public class WalletClient {

    private static final String TAG = WalletClient.class.getSimpleName();
    private static final String USER_AGENT = String.format("%s (%s;%s;%s;%s)",
            BuildConfig.APPLICATION_ID, BuildConfig.VERSION_NAME,
            BuildConfig.FLAVOR, BuildConfig.BUILD_TYPE, android.os.Build.VERSION.SDK_INT);

    private final INotificationHandler m_notificationHandler;
    private final ListeningExecutorService es;
    private WampConnection mConnection;
    private LoginData loginData;
    private ISigningWallet hdWallet;
    private List<Utxo> utxos = new ArrayList<Utxo>();
    @Nullable
    private Map<Integer, DeterministicKey> gaDeterministicKeys;
    private byte[] gaitPath;

    private String mnemonics = null;
    private Integer curBlock = null;

    public WalletClient(final INotificationHandler notificationHandler, final ListeningExecutorService es) {
        this.m_notificationHandler = notificationHandler;
        this.es = es;
    }

    private static List<String> split(final String words) {
        return new ArrayList<>(Arrays.asList(words.split("\\s+")));
    }

    public LoginData getLoginData() {
        return loginData;
    }

    private static byte[] mnemonicToPath(final String mnemonic) {
        byte[] step1 = PBKDF2SHA512.derive(mnemonic, "greenaddress_path", 2048, 64);
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter("GreenAddress.it HD wallet path".getBytes()));
        hmac.update(step1, 0, step1.length);
        byte[] step2 = new byte[64];
        hmac.doFinal(step2, 0);
        return step2;
    }

    private static byte[] extendedKeyToPath(final byte[] publicKey, final byte[] chainCode) {
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter("GreenAddress.it HD wallet path".getBytes()));
        hmac.update(chainCode, 0, chainCode.length);
        hmac.update(publicKey, 0, publicKey.length);
        byte[] step2 = new byte[64];
        hmac.doFinal(step2, 0);
        return step2;
    }

    public String getMnemonics() {
        return mnemonics;
    }

    public void disconnect() {
        // FIXME: Server should handle logout without having to disconnect
        loginData = null;
        mnemonics = null;

        hdWallet = null;
        if (mConnection != null) {
            mConnection.unsubscribe();
            try {
                mConnection.disconnect();
            } catch (final NullPointerException npe) {
                // ignore
            }
        }
    }


    public boolean canLogin() {
        return hdWallet != null;
    }

    private final OkHttpClient httpClient = new OkHttpClient();

    private String getToken() throws IOException {
        final Request request = new Request.Builder()
                .url(Network.GAIT_TOKEN_URL)
                .build();
        return httpClient.newCall(request).execute().body().string();
    }

    private String authSignature(final AuthReq request) throws SignatureException {
        try {
            final Key sk = new SecretKeySpec(request.token.getBytes(), "HmacSHA256");
            final Mac mac = Mac.getInstance(sk.getAlgorithm());
            mac.init(sk);
            final byte[] hmac = mac.doFinal(request.challenge.getBytes());
            return Base64.encodeToString(hmac, Base64.NO_WRAP);
        } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignatureException("error building signature, invalid key or no such algorithm in device");
        }
    }

    public ListenableFuture<LoginData> loginRegister(final String mnemonics, final String device_id) {

        final SettableFuture<DeterministicKey> asyncWamp = SettableFuture.create();
        final byte[] mySeed = MnemonicCode.toSeed(WalletClient.split(mnemonics), "");
        final DeterministicKey deterministicKey = HDKeyDerivation.createMasterPrivateKey(mySeed);
        final String hexMasterPublicKey = Hex.toHexString(deterministicKey.getPubKey());
        final String hexChainCode = Hex.toHexString(deterministicKey.getChainCode());
        mConnection.call("http://greenaddressit.com/login/register", Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set(deterministicKey);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, hexMasterPublicKey, hexChainCode, USER_AGENT);


        final AsyncFunction<DeterministicKey, LoginData> registrationToLogin = new AsyncFunction<DeterministicKey, LoginData>() {
            @Override
            public ListenableFuture<LoginData> apply(final DeterministicKey input) throws Exception {
                return login(new DeterministicSigningKey(input), device_id);
            }
        };

        final AsyncFunction<LoginData, LoginData> loginToSetPathPostLogin = new AsyncFunction<LoginData, LoginData>() {
            @Override
            public ListenableFuture<LoginData> apply(final LoginData input) throws Exception {
                WalletClient.this.mnemonics = mnemonics;
                return setupPath(mnemonics, input);
            }
        };

        return Futures.transform(Futures.transform(
                asyncWamp, registrationToLogin, es), loginToSetPathPostLogin, es);
    }


    public ListenableFuture<LoginData> loginRegister(final ISigningWallet signingWallet, final byte[] masterPublicKey, final byte[] masterChaincode, final byte[] pathPublicKey, final byte[] pathChaincode, final String device_id) {

        final SettableFuture<ISigningWallet> asyncWamp = SettableFuture.create();
        final String hexMasterPublicKey = Hex.toHexString(masterPublicKey);
        final String hexChainCode = Hex.toHexString(masterChaincode);

        mConnection.call("http://greenaddressit.com/login/register", Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set(signingWallet);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, hexMasterPublicKey, hexChainCode, String.format("%s HW", USER_AGENT));


        final AsyncFunction<ISigningWallet, LoginData> registrationToLogin = new AsyncFunction<ISigningWallet, LoginData>() {
            @Override
            public ListenableFuture<LoginData> apply(final ISigningWallet input) throws Exception {
                return login(input, device_id);
            }
        };

        final AsyncFunction<LoginData, LoginData> loginToSetPathPostLogin = new AsyncFunction<LoginData, LoginData>() {
            @Override
            public ListenableFuture<LoginData> apply(final LoginData input) throws Exception {
                return setupPathBTChip(extendedKeyToPath(pathPublicKey, pathChaincode), input);
            }
        };

        return Futures.transform(Futures.transform(
                asyncWamp, registrationToLogin, es), loginToSetPathPostLogin, es);
    }

    private ListenableFuture<LoginData> setupPath(final String mnemonics, final LoginData loginData) {
        final SettableFuture<LoginData> asyncWamp = SettableFuture.create();
        final String pathHex = Hex.toHexString(mnemonicToPath(mnemonics));
        mConnection.call("http://greenaddressit.com/login/set_gait_path", Void.class, new Wamp.CallHandler() {

            @Override
            public void onResult(final Object result) {
                loginData.gait_path = pathHex;
                asyncWamp.set(loginData);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, pathHex);
        return asyncWamp;
    }

    private ListenableFuture<LoginData> setupPathBTChip(final byte[] path, final LoginData loginData) {
        final SettableFuture<LoginData> asyncWamp = SettableFuture.create();
        final String pathHex = Hex.toHexString(path);
        mConnection.call("http://greenaddressit.com/login/set_gait_path", Void.class, new Wamp.CallHandler() {

            @Override
            public void onResult(final Object result) {
                loginData.gait_path = pathHex;
                asyncWamp.set(loginData);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, pathHex);
        return asyncWamp;
    }

    private ListenableFuture<RewindResult> unblindOutValue(final String rawtx, final Integer pt_idx, final Integer pointer) {
        final Transaction tx = new Transaction(Network.NETWORK, Hex.decode(rawtx));
        final TransactionOutput txOut = tx.getOutput(pt_idx);

        final ISigningWallet scanningKey = hdWallet
                .deriveChildKey(new ChildNumber(5, true))
                .deriveChildKey(new ChildNumber(pointer, true));

        final ListenableFuture<byte[]> nonceRes = scanningKey.ecdh(txOut.getNonceCommitment());
        return Futures.transform(nonceRes, new AsyncFunction<byte[], RewindResult>() {
            @Override
            public ListenableFuture<RewindResult> apply(final byte[] input) throws Exception {
                final byte[] nonceSha256 = Sha256Hash.hash(input);
                final RewindResult result = NativeSecp256k1.rangeProofRewind(
                        nonceSha256,
                        txOut.getCommitment(),
                        txOut.getRangeProof()
                );

                return Futures.immediateFuture(result);
            }
        });
    }

    private ListenableFuture<Map<?, ?>> getAlphaBalance(final Map intoMap) {
        final SettableFuture<Map<?, ?>> result = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_all_unspent_outputs", ArrayList.class,
                new Wamp.CallHandler() {
                    @Override
                    public void onResult(final Object utxo_result) {
                        final ArrayList curUtxos = (ArrayList) utxo_result;
                        final ArrayList<ListenableFuture<Long>> raw_utxos = new ArrayList<ListenableFuture<Long>>();
                        utxos.clear();
                        for (final Object utxo_ : curUtxos) {
                            final Map<?, ?> utxo = (Map<?, ?>) utxo_;
                            final String txhash = (String) utxo.get("txhash");
                            final Integer pt_idx = (Integer) utxo.get("pt_idx");
                            final Integer pointer = (Integer) utxo.get("pointer");
                            final SettableFuture<Long> utxodata = SettableFuture.create();
                            mConnection.call(
                                    "http://greenaddressit.com/txs/get_raw_unspent_output",
                                    String.class, new Wamp.CallHandler() {
                                        @Override
                                        public void onResult(final Object rawtx) {
                                            Futures.addCallback(unblindOutValue(
                                                    (String) rawtx,
                                                    pt_idx,
                                                    pointer
                                            ), new FutureCallback<RewindResult>() {
                                                @Override
                                                public void onSuccess(final @Nullable RewindResult result) {
                                                    utxodata.set(result.getValue());
                                                    utxos.add(new Utxo(
                                                            txhash,
                                                            pt_idx,
                                                            pointer,
                                                            result,
                                                            new Transaction(Network.NETWORK, Hex.decode((String) rawtx))
                                                    ));
                                                }

                                                @Override
                                                public void onFailure(final Throwable t) {
                                                    utxodata.setException(t);
                                                }
                                            });
                                        }

                                        @Override
                                        public void onError(final String errorUri, final String errorDesc) {
                                            utxodata.setException(new GAException(errorDesc));
                                        }
                                    }, txhash
                            );
                            raw_utxos.add(utxodata);
                        }
                        Futures.addCallback(Futures.allAsList(raw_utxos), new FutureCallback<List<Long>>() {
                            @Override
                            public void onSuccess(final @Nullable List<Long> results) {
                                long sum = 0;
                                for (Long val : results) {
                                    sum += val;
                                }
                                intoMap.put("satoshi", Long.toString(sum));
                                result.set(intoMap);
                            }

                            @Override
                            public void onFailure(final Throwable t) {
                                result.setException(t);
                            }
                        });
                    }

                    @Override
                    public void onError(final String errorUri, final String errorDesc) {
                        result.setException(new GAException(errorDesc));
                    }
                }
        , 0); // include zero-confs
        return result;
    }

    public ListenableFuture<Map<?, ?>> getBalance(final int subaccount) {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_balance", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Map) result);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, subaccount);
        if (Network.isCTEnabled) {
            final SettableFuture<Map<?, ?>> alphaBalance = SettableFuture.create();
            Futures.addCallback(asyncWamp, new FutureCallback<Map<?, ?>>() {
                @Override
                public void onSuccess(final @Nullable Map<?, ?> result) {
                    Futures.addCallback(getAlphaBalance(result), new FutureCallback<Map<?, ?>>() {
                        @Override
                        public void onSuccess(final @Nullable Map<?, ?> result) {
                            alphaBalance.set(result);
                        }

                        @Override
                        public void onFailure(Throwable t) {
                            alphaBalance.setException(t);
                        }
                    });
                }

                @Override
                public void onFailure(Throwable t) {
                    alphaBalance.setException(t);
                }
            });
            return alphaBalance;
        } else {
            return asyncWamp;
        }
    }


    public ListenableFuture<Map<?, ?>> getSubaccountBalance(final int pointer) {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_balance", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Map) result);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, pointer);
        return asyncWamp;
    }

    public ListenableFuture<Map<?, ?>> getTwoFacConfig() {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/get_config", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Map) result);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        });
        return asyncWamp;
    }

    public ListenableFuture<Map<?, ?>> getAvailableCurrencies() {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/login/available_currencies", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(Object result) {
                asyncWamp.set((Map) result);
            }

            @Override
            public void onError(String errorUri, String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        });
        return asyncWamp;
    }

    public ListenableFuture<Boolean> setPricingSource(final String currency, final String exchange) {
        final SettableFuture<Boolean> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/login/set_pricing_source", Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object o) {
                asyncWamp.set((Boolean) o);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, currency, exchange);
        return asyncWamp;
    }

    private ListenableFuture<AuthReq> getAuthReq() {
        final SettableFuture<AuthReq> asyncWamp = SettableFuture.create();
        try {
            final String token = getToken();
            mConnection.call("http://api.wamp.ws/procedure#authreq", String.class, new Wamp.CallHandler() {
                @Override
                public void onResult(final Object result) {
                    asyncWamp.set(new AuthReq(token, result.toString()));
                }

                @Override
                public void onError(final String errorUri, final String errorDesc) {
                    asyncWamp.setException(new GAException(errorDesc));
                }
            }, token);
        } catch (final IOException e) {
            asyncWamp.setException(e);
        }

        return asyncWamp;
    }

    private ListenableFuture<Void> doAuth(final AuthReq authReq) {
        final SettableFuture<Void> asyncWamp = SettableFuture.create();
        try {
            mConnection.call("http://api.wamp.ws/procedure#" + "auth", Void.class, new Wamp.CallHandler() {
                @Override
                public void onResult(final Object result) {
                    asyncWamp.set(null);
                }

                @Override
                public void onError(final String errorUri, final String errorDesc) {
                    asyncWamp.setException(new GAException(errorDesc));
                }
            }, authSignature(authReq));
        } catch (final SignatureException e) {
            asyncWamp.setException(e);
        }
        return asyncWamp;
    }

    public ListenableFuture<Void> connect() {
        final ListenableFuture<AuthReq> getAuthReq = Futures.transform(low_level_connect(), new AsyncFunction<Void, AuthReq>() {
            @Override
            public ListenableFuture<AuthReq> apply(final Void input) throws Exception {
                return getAuthReq();
            }
        }, es);

        final ListenableFuture<Void> connectAuthed = Futures.transform(getAuthReq, new AsyncFunction<AuthReq, Void>() {
            @Override
            public ListenableFuture<Void> apply(final AuthReq input) throws Exception {
                return doAuth(input);
            }
        }, es);

        Futures.addCallback(connectAuthed, new FutureCallback<Void>() {
            @Override
            public void onSuccess(@Nullable final Void result) {

                mConnection.subscribe("http://greenaddressit.com/block_count", Map.class, new Wamp.EventHandler() {
                    @Override
                    public void onEvent(final String topicUri, final Object event) {
                        Log.i(TAG, "BLOCKS IS " + event.toString());
                        curBlock = Integer.parseInt(((Map) event).get("count").toString());
                        m_notificationHandler.onNewBlock(curBlock);
                    }
                });


                mConnection.subscribe("http://greenaddressit.com/tx_notify", Map.class, new Wamp.EventHandler() {
                    @Override
                    public void onEvent(final String topicUri, final Object event) {
                        final Map<?, ?> res = (Map) event;
                        final String txhash = (String) res.get("txhash"),
                                value = (String) res.get("value"),
                                wallet_id = (String) res.get("wallet_id");
                        final ArrayList subaccounts = (ArrayList) res.get("subaccounts");
                        final int[] subaccounts_int = new int[subaccounts.size()];
                        for (int i = 0; i < subaccounts.size(); ++i) {
                            subaccounts_int[i] = ((Integer) subaccounts.get(i));
                        }
                        m_notificationHandler.onNewTransaction(Integer.valueOf(wallet_id),
                                subaccounts_int, Long.valueOf(value), txhash);
                    }
                });
            }

            @Override
            public void onFailure(final Throwable t) {

            }
        }, es);

        return connectAuthed;
    }

    private ListenableFuture<Void> low_level_connect() {
        final SettableFuture<Void> asyncWamp = SettableFuture.create();
        final String wsuri = Network.GAIT_WAMP_URL;
        mConnection = new WampConnection();
        final WampOptions options = new WampOptions();
        options.setReceiveTextMessagesRaw(true);
        options.setMaxMessagePayloadSize(1024 * 1024);
        options.setMaxFramePayloadSize(1024 * 1024);
        options.setTcpNoDelay(true);

        Wamp.ConnectionHandler handler = new Wamp.ConnectionHandler() {

            WebSocketMessage.Close c = null;

            @Override
            public void onOpen() {
                asyncWamp.set(null);
            }

            @Override
            public void onClose(final WebSocket.WebSocketConnectionObserver.WebSocketCloseNotification webSocketCloseNotification, final String s) {
                int code = webSocketCloseNotification.ordinal();

                if (c != null) {
                    code = c.getCode();
                    c = null;
                }

                m_notificationHandler.onConnectionClosed(code);
                gaDeterministicKeys = null;
                asyncWamp.setException(new GAException(s));

            }

            @Override
            public void onCloseMessage(final WebSocketMessage.Close close) {
                Log.i(TAG, "onCloseMessage code=" + close.getCode() + "; reason=" + close.getReason());
                c = close;
            }
        };
        try {
            mConnection.connect(wsuri, handler, options);
        } catch (final NullPointerException e) {
            // FIXME: it shouldn't be caught here, it's a workaround for the following exception
            //        which should be fixed in Autobahn-SW:
            // java.lang.NullPointerException
            //  at de.tavendo.autobahn.secure.WebSocketConnection.scheduleReconnect(WebSocketConnection.java:255)
            //  at de.tavendo.autobahn.secure.WebSocketConnection.onClose(WebSocketConnection.java:279)
            //  at de.tavendo.autobahn.secure.WebSocketConnection.connect(WebSocketConnection.java:226)
            //  at de.tavendo.autobahn.secure.WebSocketConnection.connect(WebSocketConnection.java:172)

            asyncWamp.setException(new GAException(e.toString()));
            // don't call onConnectionClosed here because it results in infinite recursive reconnection
            // in GaService
        }
        return asyncWamp;
    }

    public ListenableFuture<LoginData> login(final String mnemonics_str, final String device_id) {
        final List<String> mnemonics = Arrays.asList(mnemonics_str.split(" "));
        final ISigningWallet wallet = new DeterministicSigningKey(HDKeyDerivation.createMasterPrivateKey(MnemonicCode.toSeed(mnemonics, "")));
        this.mnemonics = mnemonics_str;

        return login(wallet, device_id);
    }

    public ListenableFuture<LoginData> login(final String device_id) {
        return login(hdWallet, device_id);
    }

    private String getRandomHexString(final int numchars) {
        final SecureRandom r = new SecureRandom();
        final StringBuilder sb = new StringBuilder();
        while (sb.length() < numchars) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, numchars);
    }

    // derive private key for signing the challenge, using 8 bytes instead of 64
    private ISigningWallet createSubpathForLogin(final ISigningWallet parentKey, final String path_hex) {
        ISigningWallet key = parentKey;
        final BigInteger path = new BigInteger(com.subgraph.orchid.encoders.Hex.decode(path_hex));
        byte[] bytes = path.toByteArray();
        if (bytes.length < 8) {
            final byte[] bytes_pad = new byte[8];
            for (int i = 0; i < bytes.length; ++i) {
                bytes_pad[7 - i] = bytes[bytes.length - 1 - i];
            }
            bytes = bytes_pad;
        }
        for (int i = 0; i < 4; ++i) {
            int b1 = bytes[i * 2];
            if (b1 < 0) {
                b1 = 256 + b1;
            }
            int b2 = bytes[i * 2 + 1];
            if (b2 < 0) {
                b2 = 256 + b2;
            }
            final int childNum = b1 * 256 + b2;
            key = key.deriveChildKey(new ChildNumber(childNum, false));
        }
        return key;
    }

    private ListenableFuture<LoginData> authenticate(final String challengeString, final ISigningWallet deterministicKey, final String device_id) {
        final SettableFuture<LoginData> asyncWamp = SettableFuture.create();

        final ListenableFuture<ECKey.ECDSASignature> signature;
        final String path_hex;
        final ISigningWallet childKey;
        final Sha256Hash challenge_sha;
        final ListenableFuture<Object> signature_arg;
        if (deterministicKey.canSignHashes()) {
            final BigInteger challenge = new BigInteger(challengeString);
            byte[] challengeBytes = challenge.toByteArray();
            // get rid of initial 0 byte if challenge > 2^31
            if (challengeBytes.length == 33 && challengeBytes[0] == 0) {
                challengeBytes = Arrays.copyOfRange(challengeBytes, 1, 33);
            }
            //Log.d(TAG, "Our address: " + address + " server challenge: " + challengeString);
            path_hex = getRandomHexString(16);
            challenge_sha = Sha256Hash.wrap(challengeBytes);
            childKey = createSubpathForLogin(deterministicKey, path_hex);

            if (Network.isSchnorrEnabled) {
                signature_arg = Futures.transform(childKey.signSchnorrHash(challenge_sha), new Function<byte[], Object>() {
                    @Nullable
                    @Override
                    public Object apply(final @Nullable byte[] input) {
                        final Integer[] ret = new Integer[64];
                        for (int i = 0; i < 64; ++i) {
                            ret[i] = input[i] & 0xff;
                        }
                        return ret;
                    }
                });
            } else {
                signature = childKey.signHash(challenge_sha);
                signature_arg = Futures.transform(signature, new Function<ECKey.ECDSASignature, Object>() {
                    @Nullable
                    @Override
                    public String[] apply(final @Nullable ECKey.ECDSASignature signature) {
                        return new String[]{signature.r.toString(), signature.s.toString()};
                    }
                });
            }
        } else {
            // btchip requires 0xB11E to skip HID authentication
            // 0x4741 = 18241 = 256*G + A in ASCII
            path_hex = "GA";
            childKey = deterministicKey.deriveChildKey(new ChildNumber(0x4741b11e));
            final String message = "greenaddress.it      login " + challengeString;
            final byte[] data = Utils.formatMessageForSigning(message);

            challenge_sha = Sha256Hash.twiceOf(data);
            signature = childKey.signMessage(message);
            signature_arg = Futures.transform(signature, new AsyncFunction<ECKey.ECDSASignature, Object>() {
                @Nullable
                @Override
                public ListenableFuture<Object> apply(final @Nullable ECKey.ECDSASignature signature) {
                    final SettableFuture<Object> res = SettableFuture.create();
                    Futures.addCallback(childKey.getPubKey(), new FutureCallback<ECKey>() {
                        @Override
                        public void onSuccess(@Nullable ECKey result) {
                            int recId;
                            for (recId = 0; recId < 4; ++recId) {
                                ECKey recovered = ECKey.recoverFromSignature(recId, signature, challenge_sha, true);
                                if (recovered != null && recovered.equals(result)) {
                                    break;
                                }
                            }
                            res.set(new String[]{signature.r.toString(), signature.s.toString(), String.valueOf(recId)});
                        }

                        @Override
                        public void onFailure(Throwable t) {
                            res.setException(t);
                        }
                    });
                    return res;
                }
            });
        }

        Futures.addCallback(signature_arg, new FutureCallback<Object>() {
            @Override
            public void onSuccess(final @Nullable Object result) {
                mConnection.call("http://greenaddressit.com/login/authenticate", Object.class, new Wamp.CallHandler() {
                    @Override
                    public void onResult(final Object loginData) {
                        try {
                            if (loginData instanceof Boolean) {
                                // login failed
                                asyncWamp.setException(new LoginFailed());
                            } else {
                                WalletClient.this.loginData = new LoginData((Map) loginData);
                                WalletClient.this.gaitPath = Hex.decode(
                                        WalletClient.this.loginData.gait_path
                                );
                                gaDeterministicKeys = new HashMap<>();
                                WalletClient.this.hdWallet = deterministicKey;

                                asyncWamp.set(WalletClient.this.loginData);
                            }
                        } catch (final ClassCastException | IOException e) {

                            asyncWamp.setException(e);
                        }
                    }

                    @Override
                    public void onError(final String errorUri, final String errorDesc) {
                        Log.i(TAG, "RESULT LOGIN " + errorDesc);
                        asyncWamp.setException(new GAException(errorDesc));
                    }
                }, result, true, path_hex, device_id, USER_AGENT);
            }

            @Override
            public void onFailure(final Throwable t) {
                asyncWamp.setException(t);
            }
        });
        return asyncWamp;
    }

    private ListenableFuture<String> getChallenge(final ISigningWallet deterministicKey) {
        return Futures.transform(deterministicKey.getIdentifier(), new AsyncFunction<byte[], String>() {
            @Override
            public ListenableFuture<String> apply(final byte[] addr) throws Exception {
                final SettableFuture<String> asyncWamp = SettableFuture.create();
                final Address address = new Address(Network.NETWORK, addr);

                mConnection.call("http://greenaddressit.com/login/get_challenge", String.class, new Wamp.CallHandler() {
                    @Override
                    public void onResult(final Object result) {
                        asyncWamp.set(result.toString());
                    }

                    @Override
                    public void onError(final String errorUri, final String errorDesc) {
                        Log.i(TAG, "RESULT LOGIN " + errorDesc);
                        asyncWamp.setException(new GAException(errorDesc));
                    }
                }, address.toString());
                return asyncWamp;
            }
        });
    }

    private ListenableFuture<String> getTrezorChallenge(final ISigningWallet deterministicKey) {
        return Futures.transform(deterministicKey.getIdentifier(), new AsyncFunction<byte[], String>() {
            @Override
            public ListenableFuture<String> apply(final byte[] addr) throws Exception {
                final SettableFuture<String> asyncWamp = SettableFuture.create();
                final Address address = new Address(Network.NETWORK, addr);

                mConnection.call("http://greenaddressit.com/login/get_trezor_challenge", String.class, new Wamp.CallHandler() {
                    @Override
                    public void onResult(final Object result) {
                        asyncWamp.set(result.toString());
                    }

                    @Override
                    public void onError(final String errorUri, final String errorDesc) {
                        Log.i(TAG, "RESULT LOGIN " + errorDesc);
                        asyncWamp.setException(new GAException(errorDesc));
                    }
                }, address.toString());
                return asyncWamp;
            }
        });
    }

    public ListenableFuture<LoginData> login(final ISigningWallet deterministicKey, final String device_id) {
        if (deterministicKey.canSignHashes()) {
            return Futures.transform(getChallenge(deterministicKey), new AsyncFunction<String, LoginData>() {
                @Override
                public ListenableFuture<LoginData> apply(final String input) throws Exception {
                    return authenticate(input, deterministicKey, device_id);
                }
            }, es);
        } else {
            return Futures.transform(getTrezorChallenge(deterministicKey), new AsyncFunction<String, LoginData>() {
                @Override
                public ListenableFuture<LoginData> apply(final String input) throws Exception {
                    return authenticate(input, deterministicKey, device_id);
                }
            }, es);
        }
    }

    public ListenableFuture<LoginData> pinLogin(final PinData data, final String pin, final String device_id) {
        final SettableFuture<DeterministicKey> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/pin/get_password", String.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object pass) {
                final String password = pass.toString();
                final String[] encrypted_splitted = data.encrypted.split(";");

                try {
                    final String decrypted = new String(AES256.decrypt(
                            Base64.decode(encrypted_splitted[1], Base64.NO_WRAP), PBKDF2SHA512.derive(
                                    password, encrypted_splitted[0], 2048, 32)));
                    final Map<String, String> json = new MappingJsonFactory().getCodec().readValue(
                            decrypted, Map.class);
                    mnemonics = json.get("mnemonic");
                    asyncWamp.set(HDKeyDerivation.createMasterPrivateKey(com.subgraph.orchid.encoders.Hex.decode(json.get("seed"))));
                } catch (final InvalidCipherTextException | IOException e) {
                    asyncWamp.setException(e);
                }
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, pin, data.ident);


        final AsyncFunction<DeterministicKey, LoginData> connectToLogin = new AsyncFunction<DeterministicKey, LoginData>() {
            @Override
            public ListenableFuture<LoginData> apply(final DeterministicKey input) {
                return login(new DeterministicSigningKey(input), device_id);
            }
        };

        return Futures.transform(asyncWamp, connectToLogin, es);
    }

    public ListenableFuture<Map<?, ?>> getMyTransactions(final Integer subaccount) {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_list_v2", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object txs) {
                final List resultList = (List) ((Map)result).get("list");
                curBlock = ((Integer) result.get("cur_block"));
                asyncWamp.set((Map) txs);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, null, null, null, null, subaccount);
        return asyncWamp;
    }

    public ListenableFuture<Map> getNewAddress(final int subaccount) {
        final SettableFuture<Map> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/fund", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object address) {
                asyncWamp.set((Map) address);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, subaccount, true);
        return asyncWamp;
    }

    private ListenableFuture<PinData> getPinData(final String pin, final SetPinData setPinData) {
        final SettableFuture<PinData> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/pin/get_password", String.class, new Wamp.CallHandler() {

            @Override
            public void onResult(final Object password) {
                try {
                    final byte[] salt = new byte[16];
                    new SecureRandom().nextBytes(salt);
                    final String salt_b64 = new String(Base64.encode(salt, Base64.NO_WRAP));

                    final String encrypted = salt_b64 + ";" + new String(
                            Base64.encode(AES256.encrypt(setPinData.json,
                                            PBKDF2SHA512.derive(password.toString(), salt_b64, 2048, 32)),
                                    Base64.NO_WRAP));

                    asyncWamp.set(new PinData(setPinData.ident, encrypted));

                } catch (final InvalidCipherTextException e) {
                    asyncWamp.setException(e);
                }
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, pin, setPinData.ident);
        return asyncWamp;
    }

    private ListenableFuture<SetPinData> setPinLogin(final String mnemonic, final byte[] seed, final String pin, final String device_name) {
        final SettableFuture<SetPinData> asyncWamp = SettableFuture.create();
        final Map<String, String> out = new HashMap<>();

        out.put("mnemonic", mnemonic);
        mnemonics = mnemonic;

        out.put("seed", new String(com.subgraph.orchid.encoders.Hex.encode(seed)));
        out.put("path_seed", new String(com.subgraph.orchid.encoders.Hex.encode(mnemonicToPath(mnemonic))));

        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            new MappingJsonFactory().getCodec().writeValue(os, out);
        } catch (final IOException e) {
            asyncWamp.setException(e);
            return asyncWamp;
        }

        mConnection.call("http://greenaddressit.com/pin/set_pin_login", String.class, new Wamp.CallHandler() {

            @Override
            public void onResult(final Object ident) {
                asyncWamp.set(new SetPinData(os.toByteArray(), ident.toString()));

            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }

        }, pin, device_name);

        return asyncWamp;
    }

    public ListenableFuture<PinData> setPin(final byte[] seed, final String mnemonic, final String pin, final String device_name) {
        return Futures.transform(setPinLogin(mnemonic, seed, pin, device_name), new AsyncFunction<SetPinData, PinData>() {
            @Override
            public ListenableFuture<PinData> apply(final SetPinData pinData) throws Exception {
                return getPinData(pin, pinData);
            }
        }, es);
    }



    public ListenableFuture<PreparedTransaction> prepareTx(final long satoshis, final String destAddress, final String feesMode, final Map<String, Object> privateData) {
        if (Network.isCTEnabled) {
            return prepareAlphaTx(
                    privateData.get("subaccount") != null ? (Integer)privateData.get("subaccount") : 0,
                    satoshis, destAddress
            );
        } else {
            final SettableFuture<PreparedTransaction.PreparedData> prepared = SettableFuture.create();
            mConnection.call("http://greenaddressit.com/vault/prepare_tx", Map.class, new Wamp.CallHandler() {
                @Override
                public void onResult(final Object preparedMap) {
                    prepared.set(new PreparedTransaction.PreparedData((Map) preparedMap, privateData, loginData.subaccounts, httpClient));
                }

                @Override
                public void onError(final String errUri, final String errDesc) {
                    prepared.setException(new GAException(errDesc));
                }
            }, satoshis, destAddress, feesMode, privateData);
            return processPreparedTx(prepared);
        }
    }

    private DeterministicKey getKeyPath(final DeterministicKey node) {
        int childNum;
        DeterministicKey nodePath = node;
        for (int i = 0; i < 32; ++i) {
            int b1 = gaitPath[i * 2];
            if (b1 < 0) {
                b1 = 256 + b1;
            }
            int b2 = gaitPath[i * 2 + 1];
            if (b2 < 0) {
                b2 = 256 + b2;
            }
            childNum = b1 * 256 + b2;
            nodePath = HDKeyDerivation.deriveChildKey(nodePath, new ChildNumber(childNum));
        }
        return nodePath;
    }

    public DeterministicKey getGaDeterministicKey(final Integer subaccount) {
        if (gaDeterministicKeys.keySet().contains(subaccount)) {
            return gaDeterministicKeys.get(subaccount);
        }

        final DeterministicKey nodePath = getKeyPath(HDKeyDerivation.deriveChildKey(new DeterministicKey(
                new ImmutableList.Builder<ChildNumber>().build(),
                Hex.decode(Network.depositChainCode),
                ECKey.fromPublicOnly(Hex.decode(Network.depositPubkey)).getPubKeyPoint(),
                null, null), new ChildNumber(subaccount != 0?3:1)));

        final DeterministicKey key = subaccount == 0 ? nodePath : HDKeyDerivation.deriveChildKey(nodePath, new ChildNumber(subaccount, false));
        gaDeterministicKeys.put(subaccount, key);
        return key;
    }

    private ListenableFuture<PreparedTransaction> prepareAlphaTx(final int subaccount, final long satoshis, final String destAddress) {
        final SettableFuture<PreparedTransaction> ret = SettableFuture.create();
        final ArrayList<Utxo> needed_utxo = new ArrayList<>();
        long collected_value_ = 0;
        int i = 0;
        final long fee = 10000;
        while (collected_value_ < satoshis + fee && i < utxos.size()) {
            collected_value_ += utxos.get(i).getRewindResult().getValue();
            needed_utxo.add(utxos.get(i));
            i += 1;
        }
        if (collected_value_ < satoshis + fee) {
            ret.setException(new GAException("Not enough funds"));
            return ret;
        }
        final long collected_value = collected_value_;
        final SettableFuture<Map> address = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/fund", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object address_) {
                address.set((Map) address_);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                address.setException(new GAException(errDesc));
            }
        }, subaccount, true);
        ListenableFuture<ScanningKeyAndScriptAndPrevoutScripts> scanning_key = Futures.transform(address, new AsyncFunction<Map, ScanningKeyAndScriptAndPrevoutScripts>() {
            @Override
            public ListenableFuture<ScanningKeyAndScriptAndPrevoutScripts> apply(final Map fundResult) throws Exception {
                return Futures.transform(hdWallet.deriveChildKey(new ChildNumber(5, true)).deriveChildKey(
                        new ChildNumber((Integer) fundResult.get("pointer"), true)).getPubKey(), new Function<DeterministicKey, ScanningKeyAndScriptAndPrevoutScripts>() {
                            @Nullable
                            @Override
                            public ScanningKeyAndScriptAndPrevoutScripts apply(final @Nullable DeterministicKey key) {
                                byte[] script = Hex.decode((String)fundResult.get("script"));
                                return new ScanningKeyAndScriptAndPrevoutScripts(
                                        key, script
                                );
                            }
                        }
                );
            }
        });
        for (int j_ = 0; j_ < needed_utxo.size(); ++j_) {
            final int j = j_;
            scanning_key = Futures.transform(scanning_key, new AsyncFunction<ScanningKeyAndScriptAndPrevoutScripts, ScanningKeyAndScriptAndPrevoutScripts>() {
                @Override
                public ListenableFuture<ScanningKeyAndScriptAndPrevoutScripts> apply(final ScanningKeyAndScriptAndPrevoutScripts input) throws Exception {
                    final ArrayList<ECKey> keys = new ArrayList<ECKey>(2);
                    int pointer = needed_utxo.get(j).getPointer();
                    keys.add(
                            HDKeyDerivation.deriveChildKey(
                                    getGaDeterministicKey(subaccount),
                                    new ChildNumber(pointer)
                            )
                    );
                    final SettableFuture<ScanningKeyAndScriptAndPrevoutScripts> res = SettableFuture.create();
                    Futures.addCallback(hdWallet.deriveChildKey(new ChildNumber(1, false)).deriveChildKey(new ChildNumber(pointer, false)).getPubKey(),
                            new FutureCallback<DeterministicKey>() {
                                @Override
                                public void onSuccess(@Nullable DeterministicKey result) {
                                    keys.add(ECKey.fromPublicOnly(result.getPubKey()));
                                    Script redeemScript = new Script(
                                            Script.createMultiSigOutputScript(
                                                    2, keys
                                            )
                                    );
                                    input.prevoutScripts.add(redeemScript);
                                    res.set(input);
                                }

                                @Override
                                public void onFailure(Throwable t) {
                                    res.setException(t);
                                }
                            }
                    );
                    return res;
                }
            });
        }
        Futures.addCallback(scanning_key, new FutureCallback<ScanningKeyAndScriptAndPrevoutScripts>() {
            @Override
            public void onSuccess(@Nullable ScanningKeyAndScriptAndPrevoutScripts result) {
                final Transaction tx = new Transaction(Network.NETWORK);
                tx.setLockTime(curBlock.longValue());  // prevent fee sniping
                tx.setFeeCT(BigInteger.valueOf(fee));
                final TxOutData[] outs = new TxOutData[2];
                final Random rand = new Random();
                int change_idx = rand.nextInt(2);
                outs[change_idx] = new TxOutData(
                        Coin.valueOf(collected_value - satoshis - fee),
                        Network.NETWORK.getP2SHHeader(),
                        result.key.getPubKey(),
                        Utils.sha256hash160(result.script)
                );
                ConfidentialAddress rcpt;
                try {
                    rcpt = new ConfidentialAddress(destAddress);
                } catch (AddressFormatException e) {
                    ret.setException(e);
                    return;
                }
                outs[1-change_idx] = new TxOutData(
                        Coin.valueOf(satoshis),
                        rcpt.getBytes()[0] & 0xff,
                        Arrays.copyOfRange(rcpt.getBytes(), 1, 34),
                        Arrays.copyOfRange(rcpt.getBytes(), 34, rcpt.getBytes().length)
                );
                byte[][] blindedValues = new byte[needed_utxo.size()][32];
                for (int i = 0; i < needed_utxo.size(); ++i) {
                    blindedValues[i] = needed_utxo.get(i).getRewindResult().getBlindingFactor();
                    tx.addInput(
                            Sha256Hash.wrap(Hex.decode(needed_utxo.get(i).getTxhash())),
                            needed_utxo.get(i).getPtIdx(),
                            new Script(TransactionInput.EMPTY_ARRAY)
                    );
                    // allow nLockTime to prevent fee sniping:
                    tx.getInput(i).setSequenceNumber(0xfffffffe);
                }
                for (int i = 0; i < outs.length; ++i) {
                    byte[][] newBlindedValues = new byte[blindedValues.length + 1][32];
                    final byte[] nextBlindingFactor;
                    if (i == outs.length - 1) {
                        try {
                            nextBlindingFactor = NativeSecp256k1.pedersenBlindSum(
                                    blindedValues,
                                    needed_utxo.size()
                            );
                        } catch (NativeSecp256k1Util.AssertFailException e) {
                            ret.setException(e);
                            return;
                        }
                    } else {
                        SecureRandom secureRandom = new SecureRandom();
                        nextBlindingFactor = new byte[32];
                        secureRandom.nextBytes(nextBlindingFactor);
                    }
                    for (int j = 0; j < blindedValues.length; ++j) {
                        newBlindedValues[j] = blindedValues[j];
                    }
                    newBlindedValues[blindedValues.length] = nextBlindingFactor;
                    blindedValues = newBlindedValues;
                    byte[] commitment;
                    try {
                        commitment = NativeSecp256k1.pedersenCommit(
                                outs[i].value.longValue(),
                                nextBlindingFactor
                        );
                    } catch (NativeSecp256k1Util.AssertFailException e) {
                        ret.setException(e);
                        return;
                    }
                    Address addr;
                    try {
                        addr = new Address(Network.NETWORK, outs[i].version, outs[i].hash);
                    } catch (WrongNetworkException e) {
                        ret.setException(e);
                        return;
                    }
                    ECKey ephemeralKey = new ECKey();
                    byte[] nonce;
                    try {
                        nonce = NativeSecp256k1.createECDHSecret(
                                ephemeralKey.getSecretBytes(),
                                outs[i].scanningPubKey
                        );
                    } catch (NativeSecp256k1Util.AssertFailException e) {
                        ret.setException(e);
                        return;
                    }
                    nonce = Sha256Hash.of(nonce).getBytes();
                    byte[] rangeProof;
                    try {
                        rangeProof = NativeSecp256k1.rangeProofSign(
                                commitment,
                                nextBlindingFactor,
                                nonce,
                                outs[i].value.longValue()
                        );
                    } catch (NativeSecp256k1Util.AssertFailException e) {
                        ret.setException(e);
                        return;
                    }
                    TransactionOutput to = new TransactionOutput(
                            Network.NETWORK,
                            tx,
                            commitment,
                            rangeProof,
                            ephemeralKey.getPubKey(),
                            addr
                    );
                    tx.addOutput(to);
                }
                ret.set(new PreparedTransaction(
                        tx,
                        needed_utxo,
                        result.prevoutScripts
                ));
            }

            @Override
            public void onFailure(Throwable t) {
                ret.setException(t);
            }
        });
        return ret;
    }

    public ListenableFuture<Transaction> signConfidentialTransaction(final PreparedTransaction tx) {
        SettableFuture<Transaction> tx_ = SettableFuture.create();
        tx_.set(tx.tx);
        ListenableFuture<Transaction> ret = tx_;
        for (int i_ = 0; i_ < tx.tx.getInputs().size(); ++i_) {
            final int i = i_;
            for (int j = 0; j < tx.tx.getInputs().size(); ++j) {
                // this is slightly confusing, but alphad requires
                // all ins to serialize with the same prevout,
                // even though this prevout is connected to only a
                // single input
                tx.tx.getInput(j).prevOut = tx.prev_utxos.get(i)
                        .getTx().getOutput(tx.prev_utxos.get(i).getPtIdx());
            }
            final Sha256Hash hash = tx.tx.hashForCTSignature(
                    i, tx.prevout_scripts.get(i).getProgram()
            );
            final ISigningWallet key = hdWallet.deriveChildKey(
                    new ChildNumber(1)
            ).deriveChildKey(
                    new ChildNumber(tx.prev_utxos.get(i).getPointer())
            );
            ret = Futures.transform(ret, new AsyncFunction<Transaction, Transaction>() {
                @Override
                public ListenableFuture<Transaction> apply(Transaction input) throws Exception {
                    return Futures.transform(key.signSchnorrHash(hash), new Function<byte[], Transaction>() {
                        @Nullable
                        @Override
                        public Transaction apply(@Nullable byte[] input) {
                            ArrayList<TransactionSignature> signature = new ArrayList<>(1);
                            signature.add(new TransactionSignature(input, Transaction.SigHash.ALL, false));
                            Script scriptSig = ScriptBuilder.createP2SHMultiSigInputScript(
                                    signature,
                                    tx.prevout_scripts.get(i)
                            );
                            List<ScriptChunk> chunks = scriptSig.getChunks();
                            ScriptBuilder builder = new ScriptBuilder();
                            builder.smallNum(0);  // Work around a bug in CHECKMULTISIG that is now a required part of the protocol.
                            byte[] zero = { 0 };
                            // re-build the script, adding zero before our signature for replacing by backend
                            builder.data(zero);
                            builder.data(chunks.get(1).data);
                            builder.data(chunks.get(2).data);
                            tx.tx.getInput(i).setScriptSig(
                                    builder.build()
                            );
                            return tx.tx;
                        }
                    });
                }
            });

        }
        return ret;
    }

    private class ConfidentialAddress extends VersionedChecksummedBytes {

        public ConfidentialAddress(String encoded) throws AddressFormatException {
            super(encoded);
        }

        public byte[] getBytes() {
            return bytes;
        }

    };

    private class ScanningKeyAndScriptAndPrevoutScripts {
        public DeterministicKey key;
        public byte[] script;
        public ArrayList<Script> prevoutScripts = new ArrayList<>();

        public ScanningKeyAndScriptAndPrevoutScripts(DeterministicKey key, byte[] script) {
            this.key = key;
            this.script = script;
        }
    };

    private class TxOutData {
        public Coin value;
        public int version;
        public byte[] scanningPubKey;
        public byte[] hash;

        public TxOutData(Coin value, int version, byte[] scanningPubKey, byte[] hash) {
            this.value = value;
            this.version = version;
            this.scanningPubKey = scanningPubKey;
            this.hash = hash;
        }
    };

    private ListenableFuture<PreparedTransaction> processPreparedTx(final ListenableFuture<PreparedTransaction.PreparedData> pt) {
        return Futures.transform(pt, new Function<PreparedTransaction.PreparedData, PreparedTransaction>() {
            @Override
            public PreparedTransaction apply(final PreparedTransaction.PreparedData input) {
                return new PreparedTransaction(input);
            }
        }, es);
    }

    public ListenableFuture<Map<?, ?>> processBip70URL(final String url) {
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/process_bip0070_url", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object data) {
                asyncWamp.set((Map) data);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, url);
        return asyncWamp;
    }

    public ListenableFuture<PreparedTransaction> preparePayreq(final Coin amount, Map<?, ?> data, final Map<String, Object> privateData) {
        final SettableFuture<PreparedTransaction.PreparedData> asyncWamp = SettableFuture.create();

        final Map dataClone = new HashMap<>();

        for (final Object tempKey : data.keySet()) {
            dataClone.put(tempKey, data.get(tempKey));
        }
        final Object key = "subaccount";

        if (privateData != null && privateData.containsKey(key)) {
            dataClone.put(key, privateData.get(key));
        }

        mConnection.call("http://greenaddressit.com/vault/prepare_payreq", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object prepared) {
                asyncWamp.set(new PreparedTransaction.PreparedData((Map) prepared, privateData, loginData.subaccounts, httpClient));
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, amount.longValue(), dataClone, privateData);

        return processPreparedTx(asyncWamp);
    }

    public ListenableFuture<Map<?, ?>> prepareSweepSocial(final byte[] pubKey, final boolean useElectrum) {
        final Integer[] pubKeyObjs = new Integer[pubKey.length];
        for (int i = 0; i < pubKey.length; ++i) {
            pubKeyObjs[i] = pubKey[i] & 0xff;
        }
        final SettableFuture<Map<?, ?>> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/prepare_sweep_social", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object prepared) {
                asyncWamp.set((Map) prepared);
            }

            @Override
            public void onError(final String errorUri, final String errorDesc) {
                asyncWamp.setException(new GAException(errorDesc));
            }
        }, new ArrayList<>(Arrays.asList(pubKeyObjs)), useElectrum);
        return asyncWamp;

    }

    public ListenableFuture<String> sendTransaction(final List<String> signatures, final Object TfaData) {
        final SettableFuture<String> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/send_tx", String.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object o) {
                asyncWamp.set(o.toString());
            }

            @Override
            public void onError(final String s, final String s2) {
                asyncWamp.setException(new GAException(s2));
            }
        }, signatures, TfaData);

        return asyncWamp;
    }

    public ListenableFuture<String> sendRawTransaction(final Transaction tx) {
        final SettableFuture<String> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/vault/send_raw_tx", String.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object o) {
                asyncWamp.set(o.toString());
            }

            @Override
            public void onError(final String s, final String s2) {
                asyncWamp.setException(new GAException(s2));
            }
        }, new String(Hex.encode(tx.bitcoinSerialize())));

        return asyncWamp;
    }

    public ListenableFuture<List<String>> signTransaction(final PreparedTransaction tx, final boolean privateDerivation) {
        final SettableFuture<List<String>> asyncWamp = SettableFuture.create();

        final Transaction t = tx.decoded;
        final List<TransactionInput> txInputs = t.getInputs();
        final List<Output> prevOuts = tx.prev_outputs;
        final List<String> signatures = new ArrayList<>(txInputs.size());
        if (hdWallet.canSignHashes()) {
            ListenableFuture<ECKey.ECDSASignature> lastSignature = Futures.immediateFuture(null);

            for (int i = 0; i < txInputs.size(); ++i) {
                final int ii = i;
                lastSignature = Futures.transform(lastSignature, new AsyncFunction<ECKey.ECDSASignature, ECKey.ECDSASignature>() {
                    @Override
                    public ListenableFuture<ECKey.ECDSASignature> apply(ECKey.ECDSASignature input) throws Exception {
                        final Output prevOut = prevOuts.get(ii);

                        final ISigningWallet account;
                        if (prevOut.subaccount == null || prevOut.subaccount == 0) {
                            account = hdWallet;
                        } else {
                            account = hdWallet
                                    .deriveChildKey(new ChildNumber(3, true))
                                    .deriveChildKey(new ChildNumber(prevOut.subaccount, true));
                        }

                        final ISigningWallet branchKey = account.deriveChildKey(new ChildNumber(prevOut.branch, privateDerivation));
                        final ISigningWallet pointerKey = branchKey.deriveChildKey(new ChildNumber(prevOut.pointer, privateDerivation));

                        final Script script = new Script(Hex.decode(prevOut.script));
                        final Sha256Hash hash = t.hashForSignature(ii, script.getProgram(), Transaction.SigHash.ALL, false);
                        return pointerKey.signHash(hash);
                    }
                });
                lastSignature = Futures.transform(lastSignature, new Function<ECKey.ECDSASignature, ECKey.ECDSASignature>() {
                    @Nullable
                    @Override
                    public ECKey.ECDSASignature apply(@Nullable ECKey.ECDSASignature input) {
                        final TransactionSignature signature = new TransactionSignature(input, Transaction.SigHash.ALL, false);
                        signatures.add(Hex.toHexString(signature.encodeToBitcoin()));
                        return null;
                    }
                });
            }
            Futures.addCallback(lastSignature, new FutureCallback<ECKey.ECDSASignature>() {
                @Override
                public void onSuccess(final @Nullable ECKey.ECDSASignature result) {
                    asyncWamp.set(signatures);
                }

                @Override
                public void onFailure(final Throwable t) {
                    asyncWamp.setException(t);
                }
            });
        } else {
            Futures.addCallback(hdWallet.signTransaction(tx,
                    Hex.decode(loginData.gait_path)), new FutureCallback<List<ECKey.ECDSASignature>>() {
                @Override
                public void onSuccess(final @Nullable List<ECKey.ECDSASignature> signatures) {
                    final List<String> result = new LinkedList<>();
                    for (final ECKey.ECDSASignature sig : signatures) {
                        final TransactionSignature txSignature = new TransactionSignature(sig, Transaction.SigHash.ALL, false);
                        result.add(Hex.toHexString(txSignature.encodeToBitcoin()));
                    }
                    asyncWamp.set(result);
                }

                @Override
                public void onFailure(final Throwable t) {
                    asyncWamp.setException(t);
                }
            });
        }
        return asyncWamp;

    }

    public Object getAppearenceValue(final String key) {
        return loginData.appearance.get(key);
    }

    /**
     * @param updateImmediately whether to not wait for server to reply before updating
     *                          the value in local settings dict (set false to wait)
     */
    public ListenableFuture<Boolean> setAppearanceValue(final String key, final Object value, final boolean updateImmediately) {
        final Object oldValue = loginData.appearance.get(key);
        if (updateImmediately) {
            loginData.appearance.put(key, value);
        }

        final Map<String, Object> newAppearance = new HashMap<>(loginData.appearance); // clone
        newAppearance.put(key, value);
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        try {
            new MappingJsonFactory().getCodec().writeValue(os, newAppearance);
        } catch (final IOException e) {
            return Futures.immediateFailedFuture(new GAException(e.getMessage()));
        }
        final String newJSON = os.toString();

        final SettableFuture<Boolean> ret = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/login/set_appearance", Map.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object o) {
                if (!updateImmediately) {
                    loginData.appearance.put(key, value);
                }
                ret.set(true);
            }

            @Override
            public void onError(final String s, final String s2) {
                Log.d(TAG, "updateAppearance failed: " + s2);
                if (updateImmediately) {
                    // restore old value
                    loginData.appearance.put(key, oldValue);
                }
                ret.setException(new GAException(s2));
            }
        }, newJSON);

        return ret;
    }

    public ListenableFuture<Object> requestTwoFacCode(final String method, final String action) {
        return requestTwoFacCode(method, action, null);
    }

    public ListenableFuture<Object> requestTwoFacCode(final String method, final String action, final Object data) {
        final SettableFuture<Object> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/request_" + method, Object.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set(result);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
                Log.e(TAG, errDesc);
            }
        }, action, data);
        return asyncWamp;
    }

    public ISigningWallet getHdWallet() {
        return hdWallet;
    }

    public ListenableFuture<ArrayList> getAllUnspentOutputs() {
        final SettableFuture<ArrayList> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_all_unspent_outputs", ArrayList.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object txs) {
                asyncWamp.set((ArrayList) txs);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, 0);
        return asyncWamp;
    }

    public ListenableFuture<Transaction> getRawUnspentOutput(final Sha256Hash txHash) {
        final SettableFuture<Transaction> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/txs/get_raw_unspent_output", String.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object tx) {
                asyncWamp.set(new Transaction(Network.NETWORK, Hex.decode((String) tx)));
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, txHash.toString());
        return asyncWamp;
    }

    public ListenableFuture<Boolean> initEnableTwoFac(final String type, final String details, final Map<?, ?> twoFacData) {
        final SettableFuture<Boolean> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/init_enable_" + type, Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Boolean) result);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, details, twoFacData);
        return asyncWamp;
    }


    public ListenableFuture<Boolean> enableTwoFac(final String type, final String code) {
        final SettableFuture<Boolean> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/enable_" + type, Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Boolean) result);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, code);
        return asyncWamp;
    }

    public ListenableFuture<Boolean> enableTwoFac(final String type, final String code, final Object twoFacData) {
        final SettableFuture<Boolean> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/enable_" + type, Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Boolean) result);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, code, twoFacData);
        return asyncWamp;
    }

    public ListenableFuture<Boolean> disableTwoFac(final String type, final Map<String, String> twoFacData) {
        final SettableFuture<Boolean> asyncWamp = SettableFuture.create();
        mConnection.call("http://greenaddressit.com/twofactor/disable_" + type, Boolean.class, new Wamp.CallHandler() {
            @Override
            public void onResult(final Object result) {
                asyncWamp.set((Boolean) result);
            }

            @Override
            public void onError(final String errUri, final String errDesc) {
                asyncWamp.setException(new GAException(errDesc));
            }
        }, twoFacData);
        return asyncWamp;
    }
}
