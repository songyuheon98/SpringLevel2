package com.sparta.memo.dto;


import lombok.Getter;


@Getter
public class MemoRequestDto { // 정보 주는 Dto
    private String username;
    private String title;
    private String contents;
}
