package fr.codeonce.gateway.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Service
public class SecurityService {

    private final Logger log = LoggerFactory.getLogger(SecurityService.class);

    public static Claims parseClaims(String authToken, String secretKey) {
        Key key = toSecretKey(secretKey);
        String authTokenValue = StringUtils.removeStart(authToken, "Bearer ");
        return Jwts
                .parser()
                .setSigningKey(key)
                .parseClaimsJws(authTokenValue)
                .getBody();
    }

    public static Claims parseRSAClaims(
            String authToken,
            RSAPublicKey publicKey
    ) {
        String authTokenValue = StringUtils.removeStart(authToken, "Bearer ");
        return Jwts
                .parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(authTokenValue)
                .getBody();
    }

    @SuppressWarnings("unchecked")
    public String validateToken(
            String authToken,
            String secretKey,
            List<String> securityLevel,
            RSAPublicKey publicKey
    ) {
        try {
            List<String> roles = new ArrayList<>();
            if (secretKey != null) {
                Claims claims = parseClaims(authToken, secretKey);
                roles = claims.get("auth", List.class);
            }
            if (publicKey != null) {
                Claims claims = parseRSAClaims(authToken, publicKey);
                roles = claims.get("auth", List.class);
            }

            if (checkRoles(securityLevel, roles) || securityLevel.contains("all")) {
                return "authorized";
            } else {
                return "You don't have the permission to use this secured API.";
            }
        } catch (
                io.jsonwebtoken.security.SecurityException | MalformedJwtException e
        ) {
            log.trace("Invalid JWT signature trace: {}", e);
            return "Invalid JWT signature.";
        } catch (ExpiredJwtException e) {
            log.trace("Expired JWT token trace: {}", e);
            return "Expired JWT token.";
        } catch (UnsupportedJwtException e) {
            log.trace("Unsupported JWT token trace: {}", e);
            return "Unsupported JWT token.";
        } catch (IllegalArgumentException e) {
            log.trace("JWT token compact of handler are invalid trace: {}", e);
            return "You need to provide a JWT";
            // return "This API requires a JWT. Please enter a valid one in the headers.";
        }
    }

    private static Key toSecretKey(String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private boolean checkRoles(List<String> securityLevels, List<String> roles) {
        for (String securityLevel : securityLevels) {
            for (String role : roles) {
                if (securityLevel.equals(role)) {
                    return true;
                }
            }
        }
        return false;
    }
}
