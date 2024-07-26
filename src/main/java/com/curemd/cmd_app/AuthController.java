package com.curemd.cmd_app;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Value("${keycloak.token-uri}")
    private String keycloakTokenUrl;
    
    @Value("${keycloak.logout-uri}")
    private String logoutUri;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;
    
    @Value("${leap.url}")
    private String leapAppUrl;

    @PostMapping("/home")
    public RedirectView authenticateWithCmdApp(@RequestParam String username, @RequestParam String password, HttpServletResponse httpResponse) {
        if (authenticateWithApp1(username, password)) {
            Map<String,String> tokenMap = authenticateWithKeycloak(username, password);
            if (tokenMap != null && tokenMap.get("accessToken") != null) {
                Map<String, String> response = new HashMap<>();
                response.put("keycloak_token", tokenMap.get("accessToken"));
                storeTokenInCookie(tokenMap.get("accessToken"), httpResponse);
                storeRefreshTokenInCookie(tokenMap.get("refreshToken"), httpResponse);
                return new RedirectView("/success.html");
            } else {
                return new RedirectView("/failed.html");
            }
        } else {
            return new RedirectView("/failed.html");
        }
    }
    
    @GetMapping("/launch-leap")
    public RedirectView launchLeap() {
    	return new RedirectView(leapAppUrl);
    }

    @GetMapping("/storeTokenInCookie")
    public String storeTokenInCookie(@RequestParam String token, HttpServletResponse response) {
        Cookie cookie = new Cookie("keycloakToken", token);
        cookie.setHttpOnly(true); // Ensure the cookie is not accessible via JavaScript
        cookie.setSecure(false); // Set to true in a production environment using HTTPS
        cookie.setPath("/"); // Set the cookie path to root
        cookie.setMaxAge(7 * 24 * 60 * 60); // Set cookie expiration to 7 days
        response.addCookie(cookie);
        return "Token stored in cookie";
    }
    
    @GetMapping("/storeRefreshTokenInCookie")
    public String storeRefreshTokenInCookie(@RequestParam String token, HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", token);
        cookie.setHttpOnly(true); // Ensure the cookie is not accessible via JavaScript
        cookie.setSecure(true); // Set to true in a production environment using HTTPS
        cookie.setPath("/"); // Set the cookie path to root
        if(null == token) {
            cookie.setMaxAge(0); // to delete token
        } else {
            cookie.setMaxAge(7 * 24 * 60 * 60); // Set cookie expiration to 7 days
        }
        response.addCookie(cookie);
        System.out.println("Token stored in cookie" + token);
        return "Token stored in cookie";
    }
    
    @GetMapping("/getTokenFromCookie")
    public String getTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("keycloakToken")) {
                    return "Token from cookie: " + cookie.getValue();
                }
            }
        }
        return "No token found in cookies";
    }
    
    @GetMapping("/getRefreshTokenFromCookie")
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refreshToken")) {
                    return cookie.getValue();
                }
            }
        }
        return "No refresh token found in cookies";
    }

    private boolean authenticateWithApp1(String username, String password) {
        // Implement your App1 authentication logic here (e.g., database verification)
        return true;
    }

    private Map<String,String> authenticateWithKeycloak(String username, String password) {
    	Map<String, String> tokenMap = new HashMap<>();
    	RestTemplate restTemplate = new RestTemplate();
    	HttpHeaders headers = new HttpHeaders();
    	headers.setContentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED);

    	MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
    	request.add("client_id", clientId);
    	request.add("client_secret", clientSecret);
    	request.add("grant_type", "password");
    	request.add("username", username);
    	request.add("password", password);

    	HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(request, headers);
    	try {
    		ResponseEntity<Map> response = restTemplate.postForEntity(keycloakTokenUrl, entity, Map.class);
    		if (response.getStatusCode().is2xxSuccessful()) {
    			String accessToken = (String) response.getBody().get("access_token");
    			String refreshToken = (String) response.getBody().get("refresh_token");
    			tokenMap.put("accessToken", accessToken);
    			tokenMap.put("refreshToken", refreshToken);
    			return tokenMap;
    		} else {
    			System.out.println("Failed to get token from Keycloak. Status: " + response.getStatusCode());
    			return null;
    		}
    	} catch (Exception e) {
    		e.printStackTrace();
    		return null;
    	}
    }
    
    @GetMapping("/logout")
    public RedirectView logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        RestTemplate restTemplate = new RestTemplate();
    	HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded");
        
        String body = "client_id=" + clientId + "&client_secret=" + clientSecret + "&refresh_token=" + getRefreshTokenFromCookie(httpServletRequest);
        try {
        	 HttpEntity<String> request = new HttpEntity<>(body,headers);
             ResponseEntity<String> response = restTemplate.exchange(logoutUri, HttpMethod.POST, request, String.class);
             if(response.getStatusCode().is2xxSuccessful()) {
             	storeTokenInCookie(null, httpServletResponse);
             	storeRefreshTokenInCookie(null, httpServletResponse);
                 return new RedirectView("/index.html");
             } else {
                 return new RedirectView("/success.html");
             }
        } catch (HttpClientErrorException e) {
         	storeTokenInCookie(null, httpServletResponse);
        	storeRefreshTokenInCookie(null, httpServletResponse);
            return new RedirectView("/index.html");
        }
       
    }
    
    @GetMapping("/logout-leap")
    public ResponseEntity<String> logoutLeap(@RequestParam String token) {
        RestTemplate restTemplate = new RestTemplate();
    	HttpHeaders headers = new HttpHeaders();
//    	headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-Type", "application/x-www-form-urlencoded");
        
        String body = "client_id=" + clientId + "&client_secret=" + clientSecret + "&refresh_token=" + token;
        try {
        	 HttpEntity<String> request = new HttpEntity<>(body,headers);
             ResponseEntity<String> response = restTemplate.exchange(logoutUri, HttpMethod.POST, request, String.class);
             if(response.getStatusCode().is2xxSuccessful()) {
                 return ResponseEntity.ok("logout successfull");
             } else {
                 return new ResponseEntity<String>("logout failed", HttpStatus.BAD_REQUEST);
             }
        } catch (HttpClientErrorException e) {
            return new ResponseEntity<String>("logout failed", HttpStatus.BAD_REQUEST);
        }
       
    }
    
}

