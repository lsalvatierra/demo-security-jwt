package pe.edu.cibertec.demo_security_jwt.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

public class FiltroJwtAuth extends OncePerRequestFilter {

    //private final String KEY = "@idat2025";
    private static final String SECRET = "mi-clave-secreta-super-larga-y-segura-1234567890";
    private static final Key KEY = Keys.hmacShaKeyFor(SECRET.getBytes());

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try{
            if(validarUsoDeToken(request)){
                Claims claims = validarToken(request);
                if(claims.get("Authorities") != null){
                    cargarAutorizaciones(claims);
                }else
                    SecurityContextHolder.clearContext();
            }else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        }catch (ExpiredJwtException | UnsupportedJwtException
                | MalformedJwtException ex){
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            ((HttpServletResponse)response).sendError(
                    HttpServletResponse.SC_FORBIDDEN,
                    ex.getMessage());
        }
    }

    private void cargarAutorizaciones(Claims claims){
        List<String> autorizaciones = (List<String>)
                claims.get("Authorities");
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        claims.getSubject(),
                        null,
                        autorizaciones.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()));
        SecurityContextHolder.getContext().setAuthentication(
                authToken);
    }

    private Claims validarToken(HttpServletRequest request){
        String token = request.getHeader("Authorization").replace("Bearer ", "");

        JwtParser parser = Jwts.parser()
                .setSigningKey(KEY)
                .build();

        return parser.parseSignedClaims(token).getPayload();
    }

    private boolean validarUsoDeToken(HttpServletRequest request){
        String token = request.getHeader("Authorization");
        if(token == null || !token.startsWith("Bearer ")){
            return false;
        }
        return true;
    }

}