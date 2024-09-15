# SPRING SECURITY JWT

[스프링 시큐리티 JWT 1 : 실습 목표 및 간단한 동작 원리](https://www.youtube.com/watch?v=NPRh2v7PTZg&list=PLJkjrxxiBSFCcOjy0AAVGNtIa08VLk1EJ)

> 간단한 동작 원리
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668cff5ad3b43a6241eb6b6e)

- 회원가입

: 세션 방식이랑 차이가 없음 

- 로그인 (인증)

: 로그인 경로로 요청이 오면 원래는 UsernamePassword 이런거 다 구현안해도 SpringSecurity가 다 처리해줬었다. JWT 방식은 따로 처리를 진행해줘야 한다. 

AuthenticationManager를 통해 로그인 검증을 진행함

검증하는 방법은? 

→ DB에 저장되어있는 User 정보를 꺼내와서 UserDetailService가 UserDetails에 담아서 최종적으로 AuthenticationManager에서 검증을 하고

로그인에 성공하면 sucessfulAuth라는 method를 통해 JWT Util에서 토큰을 만들어서 응답을 줌 

⇒ 그래서 작업할 내용은

AuthenticationFilter를 만들고 AuthenticationManager 작업을 하고 회원 검증 구현하고, sucessfulAuth 메소드를 통해 토큰을 만들어서 응답해주는 과정을 처리할 예정 

- 경로 접근 (인가)

: 넘어온 토큰을 가지고 특정한 다른 admin 경로 혹은 게시판 경로에 접근할 때 토큰을 헤더에 넣어서 요청을 진행해야 함. 

1) 특정한 경로로 요청이 들어오면 SecurityAuthenticationFilter가 검증을 우선 진행하고 JWT Filter를 만들어서 필터 검증을 진행하도록 함. 

2) 만약에 토큰이 알맞게 존재하고 정보가 일치한다면 JWT Filter에서 일시적인 세션을 만드는데 SecurityContentHolder에 

3) 특정한 경로로 요청이 들어오면 세션에 있기 때문에 특정한 admin 경로에들어갈수있음 

→ 근데 이 방식은 세션을 하나의 요청에 대해 일시적으로 만듦. 요청이 끝나버리면 세션이 사라짐.

만약 또 다른 새로운 요청이 들어오면 그 헤더에 들어있는 토큰을 통해서 동일한 아이디라도 다시 세션을 만들고 그 요청이 끝나면 사라지고, 이런식으로 동작을 함 

> 프로젝트 생성 & 의존성 추가
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d013f958b03acd4c248e5)

```java
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.3'
    id 'io.spring.dependency-management' version '1.1.6'
}

group = 'com.example'
version = '0.0.1-SNAPSHOT'

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

configurations {
    compileOnly {
        extendsFrom annotationProcessor
    }
}

repositories {
    mavenCentral()
}

dependencies {
//    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
//    runtimeOnly 'com.mysql:mysql-connector-j'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'

    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-impl:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.12.3'
}

tasks.named('test') {
    useJUnitPlatform()
}

```

[[Spring] @Controller / @ResponseBody / @RestController 를 알아보자](https://happiness-life.tistory.com/entry/1-Controller-ResponseBody-RestController-를-알아보자)

> SecurityConfig 클래스
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d026e958b03acd4c248e7)

```java
package com.example.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // password 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable
        http.csrf((auth)->auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 특정 경로 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //세션 설정 (stateless 상태로 관리)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}

```

> DB 연결 및 Entity 작성
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d5080a82855381e76285e)

> 회원가입 로직 구현
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d525886d3d643f4c18ba0)

- DTO 데이터를 UserEntity로 옮겨서 최종적으로 UserRepository로 넘겨서 DB에 저장

> 로그인 로직 구현
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d55e4ceede2499082fc28)

: 로그인 요청 받아서 처리

Filter와 Manger를 구현해야하는데, 사용자 요청이 필터를 타고 들어오면, 필터가 정보를 꺼내서 Manager한테 넘겨줌. Manager가 DB로부터 회원정보를 가져와서 검증하면 successfulAuth가 동작을 함. 그러면 여기서 JWT를 생성해서 사용자한테 응답을 해주면 됨. 실패하면 unseccessful이 되는데 이러면 401 응답 코드를 주면 됨.

- 스프링 시큐리티 필터 동작 원리

클라이언트 요청이 여러개 필터를 거쳐서 controller로 향하게 되는데, 스프링 컨테이너는 톰켓이라는 서블릿컨테이너 위에서 동작한다.

클라이언트한테 요청이 오면 톰켓의 서블릿 필터들을 통과해서 스프링 부트의 컨트롤러로 전달이 됨.

그래서 이 필터를 가지고 시큐리티를 구현함

→ 클라이언트 요청을 이 필터에서 가로채서 회원 정보를 검증하고 할건데, 하나의 DelegatingFilter를 등록해서 가로챈다.

스프링 시큐리티 의존성을 추가하게 되면 서블릿 필터에서 DelegatingFilter를 등록해서 모든 요청을 가로채는데, 시큐리티 필터로 모든 요청을 가로챔

- **서블릿 필터 체인의 DelegatingFilter → Security 필터 체인 (내부 처리 후) → 서블릿 필터 체인의 DelegatingFilter**
    
    : 가로챈 요청은 SecurityFilterChain에서 처리 후 상황에 따른 거부, 리디렉션, 서블릿으로 요청 전달을 진행 

1. 로그인 요청 받기 위한 UsernamePasswordAuthentication  커스텀 필터 작성 
2. 커스텀 로그인 필터 등록 - 시큐리티 config에
3. 로그인 필터에서 `AuthenticationManager` 이걸 주입받았는데, config에서 주입 안받아주면 동작이 안됨 → Manager에 등록해서 주입해야 함 

> 로그인 필터 구현
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d58ba680e8f4b44fc981d)

- UserDetailsService 구현

(상속받아서 인터페이스 구현만 해주면 됨)

```jsx
package com.example.securityprac.service;

import com.example.securityprac.dto.CustomUserDetails;
import com.example.securityprac.entity.UserEntity;
import com.example.securityprac.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userData = userRepository.findByUsername(username);

        if(userData != null) {
            return new CustomUserDetails(userData);
        }

        return null;
    }

}

```

> JWT 발급 및 검증 클래스
> 
- JWT 발급, 검증 담당할 클래스 : **`JWTUtil`**

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d5aa4f6f909241610dca4)

중간에 . 을 통해 header, payload, signature 부분으로 구분해서 내부에 데이터 저장함.

1. Header : JWT임을 암시, 사용된 암호화 알고리즘이 들어있음
2. Payload : 실제로 사용자가 집어넣어둔 정보를 들고있음 (발급일자 등)
3. Signature : 이 토큰을 발행한 서버에서만 확인, 검증할 수 있도록 Base64 방식으로 인코딩해서 암호화를 진행함. 
- JWT는 단순 BASE64 방식으로 인코딩하기 때문에 외부에서 열람해도 되는 정보만 담아야 함 (토큰 내부에 비밀번호와 같은 값 입력 금지)
- 토큰 자체의 발급처를 확인하기 위해 사용하는 것

**JWT 암호화 방식** 

1. 양방향(암호화를 진행하면 다시 복호화 할 수 있도록) - 대칭키 (동일한 키로 진행) / 비대칭키 (퍼블릭키와 시크릿키로 다른 키로 진행) 
2. 단방향 

**JWTUtil**

: 토큰 Payload에는 username, role, 생성일, 만료일 저장 

```jsx
package com.example.securityprac.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // 객체 키를 저장할 SecretKey
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        // 이 key 는 jwt 에서 객체 타입으로 저장하면서 그 키를 암호화를 진행 해야 함
        // String type 으로 받은 시크릿 키를 객체 변수로 암호화
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 검증 진행
    public String getUsername(String token) {
        // 토큰 검증 verifyWith : 내가 가지고 있는 시크릿 키가 서버에서 생성된게 맞는지
        // parseSignedClaims : 클레임 파싱 (클레임 정보 추출) JWT의 payload 부분에 들어있는 정보
        // getPayload : 특정한 데이터 가져오기 (username 이라는 키를 가지고 있고, String type 으로 가져옴)
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰 생성
    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey) // 시크릿 키를 가지고 암호화 진행
                .compact(); // 토큰 컴팩
    }

}

```

> 로그인 성공 JWT 발급
> 

: 로그인 성공 시 JWT 발급하기 위한 구현 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668d5c78558c63ac198c9296)

- HTTP 인증 방식 - RFC 7235 정의에 따라

→ Authorization : 타입 인증토큰

ex) Authorization : **`Bearer 인증토큰string`**

> JWT 검증 필터
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668e4e0aa9b1fd82730a94f3)

: 발급받은 Token으로 특정 경로에 요청을 보내게 되면, main controller 같은 경우에는 따로 권한 없이도 접근이 가능하지만, admin 같은 경우에는 접근을 하면 거부됨. 이유는 토큰을 검증해주는 필터를 등록하지 않았기 때문

→ 이렇게 토큰을 검증해주는 필터 구현할 것임.

(한번에 요청에 대해 잠깐동안만 세션 만드는 검증 필터 구현 : 이건 한번의 요청만 기억하기 때문에 다시 요청 보내면 토큰 검증 다시 함 ⇒ stateless 상태로 관리)

```jsx
package com.example.securityprac.jwt;

import com.example.securityprac.dto.CustomUserDetails;
import com.example.securityprac.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@AllArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // jwt 를 request 에서 뽑아내서 검증 진행
        // jwt util 을 통해 검증할 메소드를 가지고 와야 함

        // request 에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization"); // request 에서 특정한 key 값을 뽑아옴

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response); // 이 필터들에 여러 체인 방식으로 엮여있는 필터들이 있는데, 그걸 종료하고 이 필터에서 받을 req, res 를 다음 필터로 넘겨줌

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // 토큰 분리해서 소멸 시간 검증
        // 접두사 제거
        System.out.println("authorization now");
        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) { // true 면 토큰 종료

            System.out.println("token expired");
            filterChain.doFilter(request, response); // 다음 필터로 넘김

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 임시 비밀번호를 만들어야 DB 를 계속 반복적으로 왔다갔다 안함
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 세션에 사용자 등록
        // 홀더에 넣으면 현재 요청에 대한 user 세션을 생성할 수 있음 
        SecurityContextHolder.getContext().setAuthentication(authToken); // 이러면 이제 특정한 경로에 접근할 수 있음

        filterChain.doFilter(request, response); // 그 다음 필터한테 방금 받은 req, res 를 넘겨주면 됨 

    }
}

```

⇒ 이제 SecurityConfig에 필터 등록해주면 됨 

```jsx
package com.example.securityprac.config;

import com.example.securityprac.jwt.JWTFilter;
import com.example.securityprac.jwt.JWTUtil;
import com.example.securityprac.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // password 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable
        http.csrf((auth)->auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 특정 경로 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //JWTFilter 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정 (stateless 상태로 관리)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}

```

> 세션 정보
> 

: 로그인한 사용자에 대해 특정한 role 값을 뽑거나 이름을 뽑는 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668e4f84675faad2fdad3d27)

JWT FIlter를 통과하는 순간 일시적으로 세션을 만들기 때문에 세션에 대한 사용자 이름을 확인할 수 있음!

- jwt는 stateless 상태로 관리되긴 하지만, 일시적인 요청에 대해서는 세션을 잠시동안 생성하기 때문에 내부 시큐리티 콘텍스트 홀더에서 사용자 정보를 꺼낼 수 있다.

```jsx
package com.example.securityprac.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
public class MainController {

    @PostMapping("/")
    public String mainP() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();

        return "Main Controller : "+name+role;
    }

}

```

> CORS 설정
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=668e5511f94819b251c1f1c2)

클라이언트가 웹브라우저로 사이트에 접속하게 되면 프론트엔드 서버에서 리액트나 뷰와 같은 페이지를 응답해줌

그러면 프론트엔드 서버는 3000번대 서버에서 테스트를 하게 되고 그 응답받은 페이지에서 특정한 내부 데이터를 API 서버에 호출하게 되면

그 API 데이터는 8080 포트에서 응답하게됨

이렇게 되면 2개의 서버 포트 번호가 다르기때문에 웹 브라우저 단에서 교차 출처 리소스를 금지시키기 때문에 데이터가 보이지않게 됨.

⇒ 그래서 백엔드 단에서 처리해줘야 함 

**처리하는 방법은 2가지**

1. SecurityConfig
    
    : 시큐리티 필터를 타는 로그인 방식 부분에는 여기에 처리해주지 않으면 토큰이 리턴되지 않음 
    
    ```jsx
    package com.example.securityprac.config;
    
    import com.example.securityprac.jwt.JWTFilter;
    import com.example.securityprac.jwt.JWTUtil;
    import com.example.securityprac.jwt.LoginFilter;
    import jakarta.servlet.http.HttpServletRequest;
    import lombok.RequiredArgsConstructor;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
    import org.springframework.web.cors.CorsConfiguration;
    import org.springframework.web.cors.CorsConfigurationSource;
    
    import java.util.Collections;
    
    @Configuration
    @EnableWebSecurity
    @RequiredArgsConstructor
    public class SecurityConfig {
    
        //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
        private final AuthenticationConfiguration authenticationConfiguration;
        private final JWTUtil jwtUtil;
    
        //AuthenticationManager Bean 등록
        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
            return configuration.getAuthenticationManager();
        }
    
        // password 암호화
        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder() {
            return new BCryptPasswordEncoder();
        }
    
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    
            http
                    .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
    
                        @Override
                        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
    
                            CorsConfiguration configuration = new CorsConfiguration();
    
                            configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                            configuration.setAllowedMethods(Collections.singletonList("*"));
                            configuration.setAllowCredentials(true);
                            configuration.setAllowedHeaders(Collections.singletonList("*"));
                            configuration.setMaxAge(3600L);
    
                            // Authorization 에 jwt 토큰을 넣어서 보내줘야 하므로 이것도 허용 시켜줘야 함
                            configuration.setExposedHeaders(Collections.singletonList("Authorization"));
    
                            return configuration;
                        }
                    })));
    
            // csrf disable
            http.csrf((auth)->auth.disable());
    
            //From 로그인 방식 disable
            http
                    .formLogin((auth) -> auth.disable());
    
            //http basic 인증 방식 disable
            http
                    .httpBasic((auth) -> auth.disable());
    
            // 특정 경로 인가 작업
            http
                    .authorizeHttpRequests((auth) -> auth
                            .requestMatchers("/login", "/", "/join").permitAll()
                            .requestMatchers("/admin").hasRole("ADMIN")
                            .anyRequest().authenticated());
    
            //JWTFilter 등록
            http
                    .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
    
            //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
            http
                    .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);
    
            //세션 설정 (stateless 상태로 관리)
            http
                    .sessionManagement((session) -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    
            return http.build();
        }
    
    }
    
    ```
    
2. MvcConfig 
    
    : 컨트롤러 단에 들어오는 데이터는 무조건 이걸로 처리 
    
    ```jsx
    package com.example.securityprac.config;
    
    import org.springframework.context.annotation.Configuration;
    import org.springframework.web.servlet.config.annotation.CorsRegistry;
    import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
    
    @Configuration
    public class CorsMvcConfig  implements WebMvcConfigurer {
    
        @Override
        public void addCorsMappings(CorsRegistry corsRegistry) {
    
            corsRegistry.addMapping("/**")
                    .allowedOrigins("http://localhost:3000");
        }
        
    }
    
    ```
    

⇒ **그래서 2가지 다 처리해줘야 함**

## JWT 심화

[스프링 JWT 심화 1 : 실습 목표](https://www.youtube.com/watch?v=SxfweG-F6JM&list=PLJkjrxxiBSFATow4HY2qr5wLvXM6Rg-BM)

> 실습 목표 & JWT 진화 & 프로젝트 세팅
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6693fb5e6813a595796c0688)

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=669514be59f57d23e8a0b6a9)

1. **Access/Refresh 토큰의 저장 위치 고려**

cf. **`XSS`**: 게시판이나 웹 메일 등에 자바 스크립트와 같은 스크립트 코드를 삽입해 개발자가 고려하지 않은 기능이 작동되게 하는 공격

**`CSRF`**:  인터넷 사용자가 자신의 의지와는 다르게 공격자가 의도한 수정, 삭제, 등록 등의 행위를 사용자가 사용하는 웹 사이트에 요청하게 만드는 공격

<aside>
💡

로컬 스토리지 : XSS 공격에 취약함 : Access 토큰 저장

httpOnly 쿠키 : CSRF 공격에 취약함 : Refresh 토큰 저장

</aside>

- Access 토큰은 중요한 권한 정보가 들어있기 때문에 XSS 공격을 받는게 나으므로 로컬 스토리지에 저장함
- Refresh 토큰 용도는 오직 토큰 재발급이기 때문에 주로 쿠키에 저장 (크게 피해를 입을 로직이 없으므로)
1. **Refresh 토큰 Rotate**

: 저장소의 특징에 맞게 해도 탈취 당할 수 있음. 그래서 Access 토큰이 만료되면 Refresh 토큰을 가지고 서버 특정 엔드포인트에 재발급을 진행하면 Refresh 토큰 또한 재발급하여 프론트엔드 측으로 응답하는 방식

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6695158a59f57d23e8a0b6ab)

⇒ 로그인 성공 핸들러, JWT 검증 필터 부분 변경할 것

: 로그인 성공 했을 때 다중 토큰 발급, JWT 검증에서도 엑세스 토큰이 만료되면 401, 400 응답을 던져볼 것

> 다중 토큰 발급
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6695166f59f57d23e8a0b6ad)

- **`Access`**: 헤더에 발급 후 프론트에서 로컬 스토리지 저장
- **`Refresh`**: 쿠키에 발급

**기존 방식 - 토큰 하나만 발급**

```jsx
// 검증에 성공 하면 아래 함수가 실행 됨
    // 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        // UserDetailsS
        // getPrincipal : 특정한 유저 확인
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        // Authority 객체를 뽑은 뒤
        // Iterator 를 통해 내부 객체 뽑아내기
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        // 토큰 받아오기
        String token = jwtUtil.createJwt(username, role, 60*60*10L); // jwt 가 살아있을 시간

        // 헤더 부분에 담아서 응답
        response.addHeader("Authorization", "Bearer " + token);
    }
```

**변경 방식 - 다중 토큰 발급**

```jsx
// 토큰 생성
public String createJwt(String category, String username, String role, Long expiredMs) {
    return Jwts.builder()
            .claim("category", category)
            .claim("username", username)
            .claim("role", role)
            .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
            .expiration(new Date(System.currentTimeMillis() + expiredMs * 1000))
            .signWith(secretKey) // 시크릿 키를 가지고 암호화 진행
            .compact(); // 토큰 컴팩
}
```

⇒ 카테고리 값 추가 (어떤 토큰인지 구분값)

```jsx
package com.example.securityprac.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // 객체 키를 저장할 SecretKey
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        // 이 key 는 jwt 에서 객체 타입으로 저장하면서 그 키를 암호화를 진행 해야 함
        // String type 으로 받은 시크릿 키를 객체 변수로 암호화
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 검증 진행
    public String getUsername(String token) {
        // 토큰 검증 verifyWith : 내가 가지고 있는 시크릿 키가 서버에서 생성된게 맞는지
        // parseSignedClaims : 클레임 파싱 (클레임 정보 추출) JWT의 payload 부분에 들어있는 정보
        // getPayload : 특정한 데이터 가져오기 (username 이라는 키를 가지고 있고, String type 으로 가져옴)
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    // 토큰 판단용 
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰 생성
    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs * 1000))
                .signWith(secretKey) // 시크릿 키를 가지고 암호화 진행
                .compact(); // 토큰 컴팩
    }

}
```

+쿠키 설정 하는 method

```jsx
private Cookie createCookie(String key, String value) {

      Cookie cookie = new Cookie(key, value);
      cookie.setMaxAge(24*60*60);
      // cookie.setSecure(true); // https 통신을 진행할 경우
      // cookie.setPath("/"); // 쿠키가 적용될 범위 설정
      cookie.setHttpOnly(true); // 자바 스크립트에서 해당 쿠키를 접근하지 못하도록 설정 

      return cookie;
  }
```

변경된 **`successfulAuthentication`**

```jsx
// 검증에 성공 하면 아래 함수가 실행 됨
    // 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        // 유저 정보 (authentication 에서 user 정보 가져옴)
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        // 유저에 대한 role 값 가져옴
        String role = auth.getAuthority();

        // 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L); // 10분
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L); // 24시간

        // 응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());

    }
```

> Access 토큰 필터 (JWTFIlter)
> 

: JWT 토큰 검증할 토큰 필터 수정 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=669516f159f57d23e8a0b6af)

프론트의 API Client로 서버측에 요청을 보낸 후 데이터를 획득하는데, 이때 권한이 필요한 경우 Access 토큰을 요청 헤더에 첨부하는데 Access 토큰 검증은 서버측 JWTFilter에 의해 진행됨.

이때 Access 토큰이 만료된 경우 특정한 상태 코드 및 메시지를 응답해야 함.

→ 사용자의 웹에서 리프레시 토큰으로 엑세스 토큰을 재발급 받을 수 있도록 

**기존 방식 - 단일 토큰**

```jsx
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // jwt 를 request 에서 뽑아내서 검증 진행
        // jwt util 을 통해 검증할 메소드를 가지고 와야 함

        // request 에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization"); // request 에서 특정한 key 값을 뽑아옴

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response); // 이 필터들에 여러 체인 방식으로 엮여있는 필터들이 있는데, 그걸 종료하고 이 필터에서 받을 req, res 를 다음 필터로 넘겨줌

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // 토큰 분리해서 소멸 시간 검증
        // 접두사 제거
        System.out.println("authorization now");
        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) { // true 면 토큰 종료

            System.out.println("token expired");
            filterChain.doFilter(request, response); // 다음 필터로 넘김

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        // 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 임시 비밀번호를 만들어야 DB 를 계속 반복적으로 왔다갔다 안함
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 세션에 사용자 등록
        // 홀더에 넣으면 현재 요청에 대한 user 세션을 생성할 수 있음
        SecurityContextHolder.getContext().setAuthentication(authToken); // 이러면 이제 특정한 경로에 접근할 수 있음

        filterChain.doFilter(request, response); // 그 다음 필터한테 방금 받은 req, res 를 넘겨주면 됨

    }
```

**변경 방식 - 다중 토큰**

```jsx
@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken); // 토큰 만료 확인
        } catch (ExpiredJwtException e) { // 만료 되었으면

            // response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            // response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 만료가 되지 않았으면 해당 토큰의 종류를 확인 (access 인지, refresh 인지)
        // 토큰이 access 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {

            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;

        }

        // 토큰 검증이 완료된 후
        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        // UserEntity 에 데이터 넣고
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken); // 해당 유저 등록
        // 로그인 된 상태로 변경 됨 

        filterChain.doFilter(request, response);

    }
```

> Refresh로 Access 토큰 재발급
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6695178d59f57d23e8a0b6b1)

1. 처음에 로그인 전송을 함 
2. 2가지 토큰(엑세스, 리프레쉬)를 응답하게 됨
3. 웹 브라우저 측에서 토큰을 관리하다가 원하는 특정한데이터를 요청할 때 엑세스 토큰을 요청 헤더에 넣어서 API 클라이언트를 통해 서버측에 보냄
4. 서버측에서 JWT FIlter에서 토큰을 검증해서 특정한 데이터를 받을 수 있는 컨트롤러에서 요청해줄 것임 
5. 엑세스 토큰이 정상적이라 원하는 데이터가 오는 경우가 있을거고, 만료되서 만료된 응답으로 가는 경우가 있을 것
6. 이때 클라이언트에서 예외 핸들링을 등록할 수 있는데, 인터프리터와 같은걸 사용해서 400 응답이 오면 예외 헨들러 코드를 실행할 수 있는데, 이때 리프레시 토큰을 서버측에 전송하면
7. 서버가 리프레시 토큰을 받아서 새로운 엑세스 토큰을 만들어줌 

⇒ 이때 Reissue 로직을 만들 것

```jsx
package com.example.securityprac.controller;

import com.example.securityprac.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;

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

        // 토큰에서 username, role 꺼내서
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT (새로운 access 토큰을 생성)
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);

        // response (응답 헤더에 access 토큰 키에 새로운 access 토큰을 넣어)
        response.setHeader("access", newAccess);

        return new ResponseEntity<>(HttpStatus.OK);
    }
}

```

+추가로 SecurityConfig에 경로 인가

```jsx
http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/reissue").permitAll() // 모든 사람이 사용할 수 있도록 permitAll
                        // 엑세스 토큰이 만료된 상태로 접근하기 때문에 로그인이 불가능한 상태라
                        // reissue 경로는 permitAll!
                        .anyRequest().authenticated());
```

> Refresh Rotate
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6695183e59f57d23e8a0b6b3)

Reissue 엔드포인트에서 리프레시 토큰을 받아 Access 토큰 갱신시 Refresh 토큰도 같이 갱신하는 방법

- 장점
    - 보안성 강화
    - 로그인 지속시간이 길어짐

⇒ 추가작업? : 발급했던 리프레시 토큰을 모두 기억한 뒤, Rotate 이전의 리프레시 토큰은 사용하지 못하도록 해야 함 

```jsx
package com.example.securityprac.controller;

import com.example.securityprac.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class ReissueController {

    private final JWTUtil jwtUtil;

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

        // 토큰에서 username, role 꺼내서
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        // make new JWT (새로운 access, refresh 토큰을 생성)
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // response (응답 헤더에 access 토큰 키에 새로운 access 토큰을 넣어)
        response.setHeader("access", newAccess);
        response.addCookie(createCookie("refresh", newRefresh)); // 리프레시 토큰은 쿠키로 응답해주므로 addCookie

        return new ResponseEntity<>(HttpStatus.OK);
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

```

- 주의점!!!
    
    : Rotate 되기 이전의 토큰을 가지고 서버측으로 가도 인증이 되기 때문에 서버측에서 발급했던 Refresh들을 기억한 뒤 블랙리스트 처리를 진행하는 로직을 작성해야 함 
    

> Refresh 토큰 서버측 저장
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=6695197459f57d23e8a0b6b5)

: 단순하게 JWT를 발급하여 클라이언트측으로 전송하면 인증/인가에 대한 주도권 자체가 클라이언트측에 맡겨진다.

JWT를 탈취하여 서버측으로 접근할 경우 JWT가 만료되기 까지 서버측에서는 그것을 막을 수 없으며, 프론트측에서 토큰을 삭제하는 로그아웃을 구현해도 이미 복제가 되었다면 피해를 입을 수 있다.

이런 문제를 해결하기 위해 생명주기가 긴 Refresh 토큰은 발급시 서버측 저장소에 기억해두고 기억되어 있는 Refresh 토큰만 사용할 수 있도록 서버측에서 주도권을 가질 수 있다.

**구현 방법**

- 발급시에 Refresh 토큰을 mysql이나 reddis 등 서버측 저장소에 저장해둔다
- 갱신시에 기존 리프레시 토큰을 삭제하고 새로 발급한 리프레시 토큰을 저장해둔다.

추가로) 로그아웃할때 해당 토큰을 삭제해주는 작업도 진행해야 함

1. 토큰 저장소 구현

: RDB 또는 Redis와 같은 DB를 통해 저장 

이때 Redis의 경우 TTL 설정을 통해 생명주기가 끝난 토큰은 자동으로 삭제할 수 있는 장점이 있음 

(RDB의 경우 따로 그걸 삭제해주는 스케줄러 로직을 작성해줘야 해서 조금 귀찮음)

```jsx
package com.example.securityprac.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class RefreshEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;
    private String refresh;
    private String expiration;

}

```

```jsx
package com.example.securityprac.repository;

import com.example.securityprac.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    // refresh 토큰 존재 확인
    Boolean existsByRefresh(String refresh);

    @Transactional
    void deleteByRefresh(String refresh);

}

```

1. 로그인시 토큰 저장, reissue 경로에서 새로 만든 토큰 저장하고 기존 토큰을 삭제하는 로직 
- 로그인이 성공하면 **LoginSuccessHandler**를 통해 토큰 발급

: 이때 리프레시 토큰 저장소에 토큰 저장만 시켜주면 됨

```jsx
// 검증에 성공 하면 아래 함수가 실행 됨
// 로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
@Override
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

    // 유저 정보 (authentication 에서 user 정보 가져옴)
    String username = authentication.getName();

    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
    GrantedAuthority auth = iterator.next();
    // 유저에 대한 role 값 가져옴
    String role = auth.getAuthority();

    // 토큰 생성
    String access = jwtUtil.createJwt("access", username, role, 600000L); // 10분
    String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L); // 24시간

    // 토큰을 생성하고 난 이후에 토큰이 저장될 수 있도록
    addRefreshEntity(username, refresh, 86400000L);

    // 응답 설정
    response.setHeader("access", access);
    response.addCookie(createCookie("refresh", refresh));
    response.setStatus(HttpStatus.OK.value());

}

private void addRefreshEntity(String username, String refresh, Long expiredMs) {

    Date date = new Date(System.currentTimeMillis() + expiredMs);

    RefreshEntity refreshEntity = new RefreshEntity();
    // 전달 받은 값 다 초기화
    refreshEntity.setUsername(username);
    refreshEntity.setRefresh(refresh);
    refreshEntity.setExpiration(date.toString()); // 만료 일자

    // 해당 토큰 저장할 수 있도록 entity 전달
    refreshRepository.save(refreshEntity);
}
```

1. Reissue시, 리프레시 토큰을 받아서 검증하고 다시 리프레시를 로테이트

```jsx
// 리프레시 토큰 검증
// DB에 저장되어 있는지 확인
Boolean isExist = refreshRepository.existsByRefresh(refresh);
if (!isExist) {
   //response body
   return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
}
```

이제 refresh 로테이트를 통해 새로운 리프레시 토큰을 만들어서 클라이언트한테 전달해줄때, 새로운 리프레시 토큰을 저장해주고 기존에 저장되어있던 토큰을 삭제해줌

(토큰을 만든 이후에 진행되어야 함)

```jsx
// Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
refreshRepository.deleteByRefresh(refresh);
addRefreshEntity(username, newRefresh, 86400000L);
```

```jsx
private void addRefreshEntity(String username, String refresh, Long expiredMs) {

    Date date = new Date(System.currentTimeMillis() + expiredMs);

    RefreshEntity refreshEntity = new RefreshEntity();
    refreshEntity.setUsername(username);
    refreshEntity.setRefresh(refresh);
    refreshEntity.setExpiration(date.toString());

    refreshRepository.save(refreshEntity);
}
```

- 전체코드로 보면?

```jsx
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

```

**필수적으로 알아야 할 것** 

리프레시 토큰 저장소에서 토큰이 점점 쌓임. 기한이 지난 토큰이 생길수도 있는데, Redis 같은 경우에는 TTL 설정을 통해 리프레시 토큰이 삭제되게 할 수 있는데, 그렇지 않으면 (Mysql 처럼) 토큰이 쌓이게 된다. 이런 경우에는 하루에 한번씩 스케줄 작업을 통해 토큰을 주기적으로 삭제해야 한다. 

> 로그아웃
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=66951a3959f57d23e8a0b6b7)

로그아웃 버튼 클릭시, 프론트엔드에서는 로컬 스토리지에 존재하는 엑세스 토큰을 삭제하고 서버측으로 리프레시 토큰을 전송해서 나머지 부분은 서버측에서 진행해주면 됨

서버측에서는 리프레시 토큰을 받아서 쿠키 초기화 후, 리프레시 토큰을 삭제 (reissue를 못하도록)

1. DB에 저장하고 있는 리프레시 토큰 삭제
2. 리프레시 토큰 쿠키 null로 변경

⇒ 스프링 시큐리티에서 로그아웃 기능이 기본적으로 활성화되는데, 이때 클래스의 위치는 필터단임. 그래서 커스텀 필터를 시큐리티 필터단에서 구현할 것

```jsx
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
```

1. 만들어둔 필터를 SecurityConfig에 등록

```jsx
package com.example.securityprac.config;

import com.example.securityprac.jwt.CustomLogoutFilter;
import com.example.securityprac.jwt.JWTFilter;
import com.example.securityprac.jwt.JWTUtil;
import com.example.securityprac.jwt.LoginFilter;
import com.example.securityprac.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // password 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        // Authorization 에 jwt 토큰을 넣어서 보내줘야 하므로 이것도 허용 시켜줘야 함
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));

        // csrf disable
        http.csrf((auth)->auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 특정 경로 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/reissue").permitAll() // 모든 사람이 사용할 수 있도록 permitAll
                        // 엑세스 토큰이 만료된 상태로 접근하기 때문에 로그인이 불가능한 상태라
                        // reissue 경로는 permitAll!
                        .anyRequest().authenticated());

        // JWTFilter 등록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class);

        // 로그아웃 필터 등록 
        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);

        //세션 설정 (stateless 상태로 관리)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

}
```

> 추가적 보안 구상
> 

[개발자 유미 | 커뮤니티](https://www.devyummi.com/page?id=66951a9459f57d23e8a0b6b9)
