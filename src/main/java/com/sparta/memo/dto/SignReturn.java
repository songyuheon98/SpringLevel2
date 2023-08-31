package com.sparta.memo.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignReturn {
    String msg;
    int statusCode;

    public SignReturn() {
    }

    public SignReturn(String msg, int statusCode) {
        this.msg = msg;
        this.statusCode = statusCode;
    }
}
