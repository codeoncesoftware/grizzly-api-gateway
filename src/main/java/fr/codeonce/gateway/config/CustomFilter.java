package fr.codeonce.gateway.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.codeonce.gateway.service.APIService;
import fr.codeonce.gateway.service.SecurityAuthMS;
import fr.codeonce.gateway.service.SecurityService;
import fr.codeonce.grizzly.common.runtime.RuntimeQueryRequest;
import fr.codeonce.grizzly.common.runtime.RuntimeRequest;
import fr.codeonce.grizzly.common.runtime.resource.CreateResourceRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.apache.commons.lang.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Component
public class CustomFilter
        extends AbstractGatewayFilterFactory<CustomFilter.Config> {

    @Autowired
    private APIService apiService;

    @Autowired
    private SecurityService securityFilter;

    @Autowired
    private SecurityAuthMS securityAuthMS;

    final Logger logger = LoggerFactory.getLogger(CustomFilter.class);
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String IDENTITYPROVIDER = "identityProvider";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String HEADER_ACCEPT = "accept";

    @Value("${grizzly-api-runtime.ribbon.listOfServers}")
    private String runtimeUri;

    @Value("${grizzly.client_id}")
    private String grizzlyPredefinedClientId;

    @Value("${grizzly.client_secret}")
    private String grizzlyPredefinedClientSecret;

    public CustomFilter() {
        super(Config.class);
    }

    static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            if (
                    exchange.getRequest().getURI().getPath().startsWith("/api") ||
                            exchange.getRequest().getURI().getPath().startsWith("/function") ||
                            exchange
                                    .getRequest()
                                    .getURI()
                                    .getPath()
                                    .startsWith("/runtime/iam/oauth2") ||
                            exchange
                                    .getRequest()
                                    .getURI()
                                    .getPath()
                                    .startsWith("/runtime/frontRedirect")
            ) {
                return chain.filter(exchange);
            } else {
                String authorizedMessage = "authorized";
                logger.debug("Apply method is EXECUTED");

                StopWatch stopWatch = new StopWatch();
                stopWatch.start("handle execution request");
                logger.debug(
                        "Request Recieved : Method {} with path {}",
                        exchange.getRequest(),
                        exchange.getRequest().getURI().getPath()
                );
                logger.info(
                        "Request Recieved : Method {} with path {}",
                        exchange.getRequest(),
                        exchange.getRequest().getURI().getPath()
                );

                try {
                    String requestType = exchange
                            .getRequest()
                            .getURI()
                            .getPath()
                            .substring(
                                    1,
                                    exchange
                                            .getRequest()
                                            .getURI()
                                            .getPath()
                                            .indexOf(
                                                    '/',
                                                    exchange.getRequest().getURI().getPath().indexOf('/') + 1
                                            )
                            );
                    List<String> pathParts = new ArrayList<String>(
                            Arrays.asList(
                                    exchange.getRequest().getURI().getPath().substring(1).split("/")
                            )
                    );
                    if (requestType.equals("runtime") && pathParts.size() == 2) {
                        forwardHealthCheck(exchange, pathParts.get(1));
                    }
                    if (
                            exchange.getRequest().getURI().getPath().indexOf("/runtime/logs") ==
                                    0
                    ) {
                        exchange =
                                forwardStaticResource(
                                        exchange,
                                        exchange.getRequest().getURI().getPath()
                                );
                        return chain.filter(exchange);
                    } else if (
                            exchange
                                    .getRequest()
                                    .getURI()
                                    .getPath()
                                    .indexOf("/runtime/static") ==
                                    0 ||
                                    exchange
                                            .getRequest()
                                            .getURI()
                                            .getPath()
                                            .indexOf("/runtime/cache") ==
                                            0
                    ) {
                        exchange =
                                forwardStaticResource(
                                        exchange,
                                        exchange.getRequest().getURI().getPath()
                                );
                        return chain.filter(exchange.mutate().build());
                    } else if (requestType.equals("runtime") && pathParts.size() > 2) {
                        String containerId = exchange
                                .getRequest()
                                .getURI()
                                .getPath()
                                .substring(requestType.length() + 2)
                                .substring(
                                        0,
                                        exchange
                                                .getRequest()
                                                .getURI()
                                                .getPath()
                                                .substring(requestType.length() + 2)
                                                .indexOf('/', 0)
                                );
                        String resourcePath = exchange
                                .getRequest()
                                .getURI()
                                .getPath()
                                .substring(requestType.length() + containerId.length() + 2);
                        StopWatch watchResource = new StopWatch();
                        watchResource.start("watch resource");
                        logger.info(
                                "forwarded from {}",
                                exchange.getRequest().getHeaders().getFirst("Host")
                        );
                        logger.info(
                                "forwarded url from {}",
                                exchange.getRequest().getURI()
                        );
                        logger.info(
                                "forwarded uri from {}",
                                exchange.getRequest().getPath()
                        );

                        logger.info("resourcePath:{}", resourcePath);
                        logger.info("getMethod:{}", exchange.getRequest().getMethod());
                        logger.info(
                                "getHeaders:{}",
                                exchange.getRequest().getHeaders().getFirst(HEADER_ACCEPT)
                        );

                        RuntimeResource resource = apiService.getResource(
                                containerId,
                                resourcePath,
                                exchange.getRequest().getMethod().toString(),
                                exchange.getRequest().getHeaders().getFirst(HEADER_ACCEPT)
                        );
                        watchResource.stop();
                        logger.info("Resource {}", resource);
                        try {
                            if (resource.getPath() != null) {
                                if (resource.getServiceURL() != null) {
                                    authorizedMessage =
                                            checkTokenValidation(exchange, resource, chain);

                                    if (authorizedMessage.equals("authorized")) {
                                        if (
                                                resource.getExecutionType() != null &&
                                                        (
                                                                resource.getExecutionType().equalsIgnoreCase("Query") ||
                                                                        resource.getExecutionType().equalsIgnoreCase("FILE")
                                                        )
                                        ) {
                                            exchange =
                                                    forwardDBQuery(
                                                            resource,
                                                            exchange,
                                                            containerId,
                                                            resourcePath
                                                    );
                                            return chain.filter(exchange.mutate().build());
                                        }
                                    } else {
                                        exchange =
                                                forwardSecurityError(exchange, authorizedMessage, "401");
                                        return chain.filter(exchange.mutate().build());
                                    }
                                } else {
                                    if (
                                            resource.getCustomQuery().getCollectionName() != null ||
                                                    resource
                                                            .getCurrentMicroservicetype()
                                                            .equals("authentication microservice") ||
                                                    (
                                                            resource.getFunctions() != null &&
                                                                    !resource.getFunctions().isEmpty()
                                                    ) ||
                                                    resource.getExecutionType().equals("File")
                                    ) {
                                        authorizedMessage =
                                                checkTokenValidation(exchange, resource, chain);

                                        if (authorizedMessage.equals("authorized")) {
                                            if (
                                                    resource.getExecutionType() != null &&
                                                            (
                                                                    resource
                                                                            .getExecutionType()
                                                                            .equalsIgnoreCase("Query") ||
                                                                            resource.getExecutionType().equalsIgnoreCase("FILE")
                                                            )
                                            ) {
                                                StopWatch queryHandlingWatch = new StopWatch();
                                                queryHandlingWatch.start();
                                                exchange =
                                                        forwardDBQuery(
                                                                resource,
                                                                exchange,
                                                                containerId,
                                                                resourcePath
                                                        );
                                                queryHandlingWatch.stop();

                                                return chain.filter(exchange.mutate().build());
                                            } else {
                                                forwardTransformationQuery(
                                                        resource,
                                                        exchange,
                                                        containerId,
                                                        resourcePath
                                                );
                                            }
                                        } else {
                                            exchange =
                                                    forwardSecurityError(
                                                            exchange,
                                                            authorizedMessage,
                                                            "401"
                                                    );
                                            return chain.filter(exchange.mutate().build());
                                        }
                                    } else {
                                        authorizedMessage = "You must provide a collection name";
                                        exchange =
                                                forwardSecurityError(exchange, authorizedMessage, "400");
                                        return chain.filter(exchange.mutate().build());
                                    }
                                }
                            } else {
                                authorizedMessage =
                                        "This API URL is not valid or no longer exists.";
                                exchange =
                                        forwardSecurityError(exchange, authorizedMessage, "404");
                                return chain.filter(exchange.mutate().build());
                            }
                        } catch (Exception e) {
                            logger.info("message {}", e.getMessage());
                        }
                    }
                } catch (RuntimeException e) {
                    logger.error("Url malformed", e);
                    exchange = forwardSecurityError(exchange, authorizedMessage, "400");
                    return chain.filter(exchange.mutate().build());
                }
                return chain.filter(exchange.mutate().build());
            }
        };
    }

    private Mono<Void> forwardHealthCheck(
            ServerWebExchange exchange,
            String containerId
    ) {
        JSONObject jsonObject = new JSONObject(
                apiService.getHealthCheck(containerId)
        );
        byte[] bytes = jsonObject.toString(4).getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Flux.just(buffer));
    }

    private ServerWebExchange forwardStaticResource(
            ServerWebExchange exchange,
            String path
    ) {
        ServerHttpRequest request = exchange
                .getRequest()
                .mutate()
                .path(path)
                .build();
        return exchange.mutate().request(request).build();
    }

    private String checkTokenValidation(
            ServerWebExchange exchange,
            RuntimeResource resource,
            GatewayFilterChain chain
    ) throws JsonProcessingException, InterruptedException, ExecutionException {
        String key = resource.getSecurityKey();
        String runtimeUrl = resource.getAuthMSRuntimeUrl();
        List<String> securityLevel = resource.getSecurityLevel();
        String authMsg = "authorized";
        logger.info("authms runtime url {}", resource.getAuthMSRuntimeUrl());

        if (!securityLevel.contains("public")) {
            String token = exchange
                    .getRequest()
                    .getHeaders()
                    .getFirst("Authorization");

            if (securityAuthMS.isdelegatedSecurityToAuthMicroservice(runtimeUrl)) {
                RSAPublicKey pk;
                pk = securityAuthMS.getPublicKey(resource);
                authMsg = securityFilter.validateToken(token, null, securityLevel, pk);
            } else {
                authMsg = securityFilter.validateToken(token, key, securityLevel, null);
            }
        }

        logger.info("authmsg" + authMsg);
        return authMsg;
    }

    private ServerWebExchange forwardDBQuery(
            RuntimeResource resource,
            ServerWebExchange exchange,
            String containerId,
            String resourcePath
    ) throws IOException, InterruptedException, ExecutionException {
        logger.info("forward db query");
        ServerHttpRequest request = exchange
                .getRequest()
                .mutate()
                .path("/runtime/query/" + containerId.toLowerCase() + resourcePath)
                .build();
        ServerWebExchange mutatedExchange = exchange
                .mutate()
                .request(request)
                .build();

        RuntimeQueryRequest runtimeRequest = apiService.getRuntimeQueryRequest(
                resource
        );

        runtimeRequest.setCurrentMicroservicetype(
                resource.getCurrentMicroservicetype()
        );

        if (
                resource
                        .getCurrentMicroservicetype()
                        .equals("authentication microservice")
        ) {
            JSONObject queryJson = new JSONObject();

            HttpHeaders mutableHeaders = new HttpHeaders();
            mutableHeaders.add("authMSRuntimeUrl", resource.getAuthMSRuntimeUrl());

            ServerHttpRequest request1 = mutatedExchange
                    .getRequest()
                    .mutate()
                    .headers(h -> h.addAll(mutableHeaders))
                    .build();
            mutatedExchange.mutate().request(request1).build();
            setParsedQuery(exchange, queryJson);

            runtimeRequest.setParsedQuery(queryJson.toString());
        }
        String authToken = exchange
                .getRequest()
                .getHeaders()
                .getFirst("Authorization");
        if (
                !resource.getSecurityLevel().contains("public") &&
                        StringUtils.isNotBlank(authToken)
        ) {
            Claims claims;
            if (
                    securityAuthMS.isdelegatedSecurityToAuthMicroservice(
                            resource.getAuthMSRuntimeUrl()
                    )
            ) {
                RSAPublicKey pk = securityAuthMS.getPublicKey(resource);
                claims = SecurityService.parseRSAClaims(authToken, pk);
            } else {
                claims =
                        SecurityService.parseClaims(authToken, resource.getSecurityKey());
                runtimeRequest.setUsername(claims.getSubject());
            }
        }
        try {
            if (exchange.getRequest().getHeaders().getFirst("query") != null) {
                exchange
                        .getRequest()
                        .getHeaders()
                        .add("q", exchange.getRequest().getHeaders().getFirst("query"));
            }

            HttpHeaders mutableHeaders = new HttpHeaders();
            mutableHeaders.add(
                    "query",
                    new ObjectMapper().writeValueAsString(runtimeRequest)
            );

            ServerHttpRequest request1 = mutatedExchange
                    .getRequest()
                    .mutate()
                    .headers(h -> h.addAll(mutableHeaders))
                    .build();
            mutatedExchange.mutate().request(request1).build();
            return mutatedExchange;
        } catch (Exception e) {
            logger.debug(
                    "An error has been occured while parsing object {}",
                    e.getMessage()
            );
        }
        return mutatedExchange;
    }

    private Mono<Void> forwardTransformationQuery(
            RuntimeResource resource,
            ServerWebExchange exchange,
            String containerId,
            String resourcePath
    ) {
        RuntimeRequest<?> runtimeRequest = apiService.getRuntimeRequest(
                containerId,
                resource
        );
        ServerHttpRequest request = exchange
                .getRequest()
                .mutate()
                .path("/runtime/" + runtimeRequest.getExecutionType().toLowerCase())
                .build();
        exchange.mutate().request(request).build();

        try {
            Flux<DataBuffer> body = exchange.getRequest().getBody();
            if (body == null) {
                return null;
            } else {
                Mono<String> bodyMono = DataBufferUtils
                        .join(body)
                        .map(dataBuffer -> {
                            byte[] bytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(bytes);
                            DataBufferUtils.release(dataBuffer);
                            return new String(bytes, StandardCharsets.UTF_8);
                        });
                String requestBody = new ObjectMapper()
                        .writeValueAsString(runtimeRequest) +
                        bodyMono.block();
                byte[] bytes = requestBody.getBytes(StandardCharsets.UTF_8);
                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

                return exchange.getResponse().writeWith(Flux.just(buffer));
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    private ServerWebExchange forwardSecurityError(
            ServerWebExchange exchange,
            String authorizedMessage,
            String code
    ) {
        ServerHttpRequest request = exchange
                .getRequest()
                .mutate()
                .header("code", code)
                .header("authorizedMessage", authorizedMessage)
                .path("/runtime/error")
                .build();

        return exchange.mutate().request(request).build();
    }

    private void setParsedQuery(
            ServerWebExchange exchange,
            JSONObject queryJson
    ) {
        Map<String, String> queryParams = exchange
                .getRequest()
                .getQueryParams()
                .toSingleValueMap();

        if (queryParams.get(CLIENT_ID) != null) {
            queryJson.put(CLIENT_ID, queryParams.get(CLIENT_ID));
        }
        if (queryParams.get(CLIENT_SECRET) != null) {
            queryJson.put(CLIENT_SECRET, queryParams.get(CLIENT_SECRET));
        }
        if (queryParams.get(IDENTITYPROVIDER) != null) {
            queryJson.put(IDENTITYPROVIDER, queryParams.get(IDENTITYPROVIDER));
        }
        if (queryParams.get(USERNAME) != null) {
            queryJson.put(USERNAME, queryParams.get(USERNAME));
        }
        if (queryParams.get(PASSWORD) != null) {
            queryJson.put(PASSWORD, queryParams.get(PASSWORD));
        }
        if (queryParams.get("redirect_uri") != null) {
            queryJson.put("redirect_uri", queryParams.get("redirect_uri"));
        }
    }

    private RuntimeResource createReourceOnTheFly(
            String containerId,
            RuntimeResource resource,
            String authorizedMessage,
            ServerWebExchange exchange,
            String resourcePath
    ) throws IOException {
        List<String> parameterNames = new ArrayList<String>();
        while (!exchange.getRequest().getQueryParams().isEmpty()) {
            String parameterName = exchange
                    .getRequest()
                    .getQueryParams()
                    .keySet()
                    .iterator()
                    .next();
            parameterNames.add(parameterName);
        }
        if (exchange.getRequest().getHeaders().getFirst("query") != null) {
            parameterNames.add(exchange.getRequest().getHeaders().getFirst("query"));
        }
        if (exchange.getRequest().getHeaders().getFirst("apikey") != null) {
            if (
                    apiService.getUserByApiKey(
                            exchange.getRequest().getHeaders().getFirst("apikey"),
                            containerId
                    )
            ) {
                CreateResourceRequest createresource = new CreateResourceRequest();
                createresource.setParsedBody(
                        new HttpServletRequestWrapper(
                                (HttpServletRequest) exchange.getRequest()
                        )
                                .getReader()
                                .lines()
                                .reduce("", (accumulator, actual) -> accumulator + actual)
                );
                createresource.setPath(resourcePath);
                createresource.setRequestparam(parameterNames);
                createresource.setHttpMethod(
                        exchange.getRequest().getMethod().toString()
                );
                try {
                    apiService.createResource(containerId, createresource);
                    resource =
                            apiService.getResource(
                                    containerId,
                                    resourcePath,
                                    exchange.getRequest().getMethod().toString(),
                                    exchange.getRequest().getHeaders().getFirst(HEADER_ACCEPT)
                            );
                    return resource;
                } catch (Exception e) {
                    logger.info(e.getMessage());
                    authorizedMessage = "url mal formed";
                }
            } else {
                authorizedMessage = "INVALID API KEY OR CONTAINER ID";
                forwardSecurityError(exchange, authorizedMessage, "401");
            }
        } else {
            authorizedMessage = "YOU NEED TO PROVIDE AN API KEY";
            forwardSecurityError(exchange, authorizedMessage, "401");
        }
        return null;
    }
}
