package org.example.utils;

import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

public class UserInfo {

    private ResponseAuthenticationMessage tgt;
    private Map<String, ResponseTGSMessage> mapSGT;
    private SecretKey dhKey;

    public UserInfo() {
        mapSGT = new HashMap<>();
        tgt = null;
        dhKey = null;
    }

    public ResponseAuthenticationMessage getTGT() {
        return tgt;
    }

    public void setTGT(ResponseAuthenticationMessage tgt) {
        this.tgt = tgt;
    }

    public ResponseTGSMessage getSGT(String command) {
        return mapSGT.get(command);
    }

    public void addSGT(String command, ResponseTGSMessage sgt) {
        mapSGT.put(command, sgt);
    }

    public SecretKey getDhKey() {
        return dhKey;
    }

    public void setDhKey(SecretKey dhKey) {
        this.dhKey = dhKey;
    }
}
