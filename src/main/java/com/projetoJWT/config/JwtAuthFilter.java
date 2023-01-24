package com.projetoJWT.config;

import com.projetoJWT.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Esta classe é chamada toda vez que uma requisição é feita pelo cliente, o que
 * garante sua autenticação em todas requisições.
 *
 * @author João Chocron
 *
 */
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * O primeiro If garante que, caso o header da requisição seja nulo ou não comece com 'Bearer ', ocorra um
     * retorno imediato e cesse o filtro. Tendo o filtro continuado, extrai o JWT
     * do header. A partir disso, através da classe JwtService, extrai as
     * informações contidas no JWT.
     * No segundo If, caso ainda não tenha autenticação, executa-se os métodos necessários para
     * que o usuário e JWT sejam autenticados
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if ( authHeader==null || !authHeader.startsWith("Bearer ") ){
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if( userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null ){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if ( jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            }
        }
        filterChain.doFilter(request, response);
    }
}
