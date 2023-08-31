package com.sparta.memo.controller;

import com.sparta.memo.dto.MemoRequestDto;
import com.sparta.memo.dto.MemoResponseDto;
import com.sparta.memo.entity.Memo;
import com.sparta.memo.entity.User;
import com.sparta.memo.service.MemoService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MemoController {
    private final MemoService memoService;

    public MemoController(MemoService memoService) {
        this.memoService = memoService;
    }

    @PostMapping("/memos")
    public MemoResponseDto createMemo(@RequestBody MemoRequestDto requestDto, HttpServletRequest req) {
        User user = (User) req.getAttribute("user");
        return memoService.createMemo(requestDto, user.getUsername());
    }

    @GetMapping("/memos")
    public List<MemoResponseDto> getMemos() {
        return memoService.getMemos();
    }

    @GetMapping("/memos/{id}")
    public MemoResponseDto getOneMemo(@PathVariable Long id) {
        return memoService.getOneMemo(id);
    }

    @PutMapping("/memos/{id}")
    public Memo updateMemo(@PathVariable Long id, @RequestBody MemoRequestDto requestDto, HttpServletRequest req) {
        User user = (User) req.getAttribute("user");

        return memoService.updateMemo(id, requestDto,user.getUsername());
    }

    @DeleteMapping("/memos/{id}")
    public ResponseEntity<String> deleteMemo(@PathVariable Long id, HttpServletRequest req) {
        User user = (User) req.getAttribute("user");

        return memoService.deleteMemo(id, user.getUsername());
    }
}