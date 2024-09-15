package com.example.securityprac.controller;

import com.example.securityprac.entity.RefreshEntity;
import com.example.securityprac.jwt.JWTUtil;
import com.example.securityprac.repository.RefreshRepository;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {

        // get refresh token
        String refresh = null;
        // 리프레시 토큰을 요청(request) 에서 뽑아는 과정
        // 쿠키 배열에 일단 다 담고
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            // 이걸 순회해서 refresh 라는 key 값을 찾아서
            if (cookie.getName().equals("refresh")) {
                // 리프레시 변수에 저장
                refresh = cookie.getValue();
            }
        }

        if (refresh == null) {
            // response status code
            // 리프레시가 없으면 error msg
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        // expired check
        // 리프레시 토큰이 만료되었는지 체크
        try {
            jwtUtil.isExpired(refresh); // jwtUtil 클래스를 통해 만료되었는지 확인
        } catch (ExpiredJwtException e) { // 만료 되었다면
            // response status code
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 여기까지 온거면 토큰이 만료되지 않은 상태
        // 토큰이 refresh 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh); // 어떤 토큰인지 확인

        if (!category.equals("refresh")) { // 만약 리프레시가 아니면
            // response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 리프레시 토큰 검증
        // DB에 저장되어 있는지 확인
        Boolean isExist = refreshRepository.existsByRefresh(refresh);
        if (!isExist) {
           //response body
           return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 토큰에서 username, role 꺼내서
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT (새로운 access, refresh 토큰을 생성)
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
        refreshRepository.deleteByRefresh(refresh);
        addRefreshEntity(username, newRefresh, 86400000L);

        // response (응답 헤더에 access 토큰 키에 새로운 access 토큰을 넣어)
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh)); // 리프레시 토큰은 쿠키로 응답해주므로 addCookie

        return new ResponseEntity<>(HttpStatus.OK);
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    // 쿠키 생성 메소드
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
