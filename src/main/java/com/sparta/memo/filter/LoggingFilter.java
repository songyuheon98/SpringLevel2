package com.sparta.memo.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j(topic = "LoggingFilter")
@Component
@Order(1)
public class LoggingFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException, IOException {
        // ServletRequest를 HttpServletRequest로 다운캐스팅하여 HTTP 관련 메서드를 사용할 수 있게 함
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        // 현재 요청의 URI를 가져옴
        String url = httpServletRequest.getRequestURI();

        // 가져온 URI를 로그에 출력
        log.info(url);

        // 요청과 응답을 다음 필터로 전달하거나, 해당 필터가 마지막 필터라면 실제 서블릿이나 JSP로 전달
        chain.doFilter(request, response);

        // 요청 처리 후 "비즈니스 로직 완료" 라는 메시지를 로그에 출력
        log.info("비즈니스 로직 완료");
    }

}