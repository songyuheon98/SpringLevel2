package com.sparta.memo.dto;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.sparta.memo.entity.Memo;
import lombok.Getter;

import java.time.LocalDateTime;


@Getter
public class MemoResponseDto { // 응답하는 Dto
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Long id;
    private String username;
    private String title;
    private String contents;
    private LocalDateTime createdAt;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private LocalDateTime modifiedAt;


    public MemoResponseDto(Memo memo) {
        this.id = memo.getId();
        this.username = memo.getUsername();
        this.title = memo.getTitle();
        this.contents = memo.getContents();
        this.createdAt = memo.getCreatedAt();
        this.modifiedAt = memo.getModifiedAt();
    }
    public MemoResponseDto(String username,String title, String contents, LocalDateTime createdAt) {
        this.username = username;
        this.title = title;
        this.contents = contents;
        this.createdAt = createdAt;
    }


    public static MemoResponseDto fromMemo(Memo memo) { // 필요한 정보만 내보내기
        return new MemoResponseDto(memo.getUsername(), memo.getTitle(), memo.getContents(), memo.getCreatedAt());
    }
}
