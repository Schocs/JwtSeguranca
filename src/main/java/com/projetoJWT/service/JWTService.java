package com.projetoJWT.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Classe responsável por extrair as informações contidas no JWT, além de gerar
 * um JWT. Também verifica a validade do token, se está expirado, por quanto
 * tempo pode ser utilizado, quando é a data de expiração.
 *
 * @author João Chocron
 *
 */
@Service
public class JWTService {

    private static final String SECRET_KEY = "432A462D4A614E645267556B586E3272357538782F413F4428472B4B62506553";

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Método que, a partir do JWT, extrai qualquer claim quando chamado
     *
     * @param token
     * @return qualquer claim a ser especificado pelo método 'extractClaim()'
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Este método utiliza o método 'extractAllClaims()' para extrair claims
     * expecíficos quando requisitado.
     *
     * @param <T>
     * @param token
     * @param claimsResolver
     * @return o claim específico requisitados pelos métodos que o chamam.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claim = extractAllClaims(token);
        return claimsResolver.apply(claim);
    }

    /**
     * Método utilizado pelo filter, extrai o username a partir de um JWT
     *
     * @param token
     * @return o username a partir de um JWT válido
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Método utilizado para obter a data de expiração do JWT
     * @param token
     * @return a data de expiração do JWT
     */
    private Date extractExpiration(String token) {
        return  extractClaim(token, Claims::getExpiration);
    }

    /**
     * Método que gera um JWT quando requisitado. O payload receberá as claims requisitadas e o sujeito que
     * realizou a requisição de criação do JWT.
     * @param extraClaims a ser inseridas no payload do JWT
     * @param userDetails
     * @return uma String de JWT com todas as informações necessárias.
     */
    public String generateToken(Map<String, Object> extraClaims , UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000*3600*24*5))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Método que gera um token sem claims extra no payload, utilizando o método generateToken acima.
     * @param userDetails
     * @return uma String de JWT com todas as informações necessárias.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Método que compara a data de execução com a data de expiração do token
     * @param token
     * @return boleano de acordo com a situação
     */
    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    /**
     * Método que verifica se o token é valido a partir do username, passado através
     * de userDetails, e se o token ainda não foi expirado.
     * @param token
     * @param userDetails
     * @return boleano de acordo com a situação
     */
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
}
