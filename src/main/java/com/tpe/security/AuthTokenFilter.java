package com.tpe.security;

import org.springframework.beans.factory.annotation.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.context.*;
import org.springframework.security.core.userdetails.*;
import org.springframework.util.*;
import org.springframework.web.filter.*;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;

public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String jwtToken = parseJwt(request);

        try {
            if(jwtToken!=null && jwtUtils.validateToken(jwtToken)){

                String userName  = jwtUtils.getUserNameFromJwtToken(jwtToken);
                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        } catch (UsernameNotFoundException e) {
            e.printStackTrace();
        }

        filterChain.doFilter(request,response);


    }
    //Bearer ey........

    private String parseJwt(HttpServletRequest request){
       String header =  request.getHeader("Authorization");
       if(StringUtils.hasText(header) && header.startsWith("Bearer ")) {
           return header.substring(7);
        }
       return null;

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        AntPathMatcher antPathMatcher = new AntPathMatcher();
         return antPathMatcher.match("/register", request.getServletPath()) ||
                 antPathMatcher.match("/login" , request.getServletPath());
    }
}
