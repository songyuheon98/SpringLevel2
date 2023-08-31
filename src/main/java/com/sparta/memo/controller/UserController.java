package com.sparta.memo.controller;

import com.sparta.memo.dto.UserDto;
import com.sparta.memo.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController // 그냥 컨트롤러라 return값 뒤에 html 붙음
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user/signup")
    public String signupPage() {
        return "signup";
    }

//    @PostMapping("/user/signup")
//    public SignReturn signup(@RequestBody UserDto requestDto) {
//        userService.signup(requestDto);
//        return new SignReturn("회원가입 성공",200);
//    }

    @PostMapping("/user/signup")
    public ResponseEntity<String> signup(@RequestBody UserDto requestDto) {
        userService.signup(requestDto);

        String jsonResponse = "{\"msg\": \"회원가입 성공\", \"statusCode\": 200}";
        return ResponseEntity.ok(jsonResponse);
    }

    @PostMapping("/user/login")
    public ResponseEntity<String> login(@RequestBody UserDto requestDto, HttpServletResponse res) {
        String jsonResponse = "{\"msg\": \"로그인 성공\", \"statusCode\": 200}";
        userService.login(requestDto, res);
        return ResponseEntity.ok(jsonResponse);
    }
}
