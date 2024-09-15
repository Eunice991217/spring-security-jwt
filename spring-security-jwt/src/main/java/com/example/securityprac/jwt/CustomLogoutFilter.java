package com.example.securityprac.jwt;
import com.example.securityprac.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;
import java.io.IOException;

@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);

    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        // path and method verify
        // 로그아웃인지 아닌지
        String requestUri = request.getRequestURI();
        if (!requestUri.matches("^\\/logout$")) {
            // 로그아웃 경로가 아니면 다음 Filter 로 넘김
            filterChain.doFilter(request, response);
            return;
        }
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {
            // 로그아웃 이더라도 POST 요청이 아니면 다음 Filter 로 넘김
            filterChain.doFilter(request, response);
            return;
        }

        // get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            // 리프레시 토큰 확인
            if (cookie.getName().equals("refresh")) {
                refresh = cookie.getValue();
            }
        }

        // refresh null check
        if (refresh == null) {
            // 리프레시 토큰이 없을 경우 예외 처리
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // expired check (만료 확인)
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 토큰이 활성화 되어 있으면
        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);
        if (!category.equals("refresh")) {
            // response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
            // response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // 로그아웃 진행
        // Refresh 토큰 DB에서 제거
        refreshRepository.deleteByRefresh(refresh);

        // Refresh 토큰 Cookie 값 0 (null 로 변경)
        Cookie cookie = new Cookie("refresh", null);
        cookie.setMaxAge(0); // 시간 값도 0 으로 변경
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }

}
