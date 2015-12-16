package com.greenaddress.greenapi;

import org.bitcoin.RewindResult;
import org.bitcoinj.core.Transaction;

public class Utxo {

    private String txhash;
    private Integer ptIdx;
    private Integer pointer;
    private RewindResult rewindResult;
    private Transaction tx;

    public Utxo(String txhash, Integer ptIdx, Integer pointer, RewindResult rewindResult, Transaction tx) {
        this.txhash = txhash;
        this.ptIdx = ptIdx;
        this.pointer = pointer;
        this.rewindResult = rewindResult;
        this.tx = tx;
    }

    public String getTxhash() {
        return txhash;
    }

    public Integer getPtIdx() {
        return ptIdx;
    }

    public Integer getPointer() {
        return pointer;
    }

    public Transaction getTx() {
        return tx;
    }

    public RewindResult getRewindResult() {
        return rewindResult;
    }
}
