package com.htakemoto.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.htakemoto.util.SecurityUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Component
public class AuthFilter extends GenericFilterBean {

    @Autowired private SecurityUtil securityUtil;
    @Autowired private ObjectMapper mapper;
    private static final String HEADER_NAME = "Authorization";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String jwtString = getAuthTokenFromHeader((HttpServletRequest) request);
        Map jwt = jwtString != null ? securityUtil.verifyJWT(jwtString) : null;
        String usr = jwt != null ? mapper.convertValue(jwt.get("usr"), String.class) : null;
        List<String> roles = jwt != null ? Arrays.asList(mapper.convertValue(jwt.get("roles"), String[].class)) : null;
        
        SecurityContext contextBeforeChainExecution = createSecurityContext(usr, roles);
        
        try {
            SecurityContextHolder.setContext(contextBeforeChainExecution);
            if (contextBeforeChainExecution.getAuthentication() != null && contextBeforeChainExecution.getAuthentication().isAuthenticated()) {
                String newJwt = securityUtil.generateJWT(usr, roles);
                ((HttpServletResponse)response).setHeader(HEADER_NAME, newJwt);
            }
            filterChain.doFilter(request, response);
        }
        finally {
            // Clear the context and free the thread local
            SecurityContextHolder.clearContext();
        }
    }
    
    private SecurityContext createSecurityContext(String usr, List<String> roles) {
        if (usr != null && roles != null) {
            SecurityContextImpl securityContext = new SecurityContextImpl();
            Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            for (String role: roles) {
                SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_"+role);
                authorities.add(authority);
            }
            Authentication authentication = new UsernamePasswordAuthenticationToken(usr, "", authorities);
            securityContext.setAuthentication(authentication);
            return securityContext;
        }
        return SecurityContextHolder.createEmptyContext();
    }

    private String getAuthTokenFromHeader(HttpServletRequest request) {
        try {
            String token = request.getHeader(HEADER_NAME);
            return StringUtils.isNotBlank(token) ? token : null;
        } catch (NullPointerException e) {
            return null;
        }
    }
}
