/*
 * Copyright © 2020 CodeOnce Software (https://www.codeonce.fr/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.codeonce.grizzly.gateway.filter;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.REQUEST_URI_KEY;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.util.StopWatch;
import org.springframework.util.StreamUtils;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import java.security.interfaces.RSAPublicKey;

import fr.codeonce.grizzly.common.runtime.RuntimeQueryRequest;
import fr.codeonce.grizzly.common.runtime.RuntimeRequest;
import fr.codeonce.grizzly.common.runtime.resource.CreateResourceRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import fr.codeonce.grizzly.gateway.service.APIService;
import io.jsonwebtoken.Claims;

/**
 * A ZUUL Filter to Intercept the HTTP Request and Forward it to the
 * Corresponding MicroService Instance Based on the Request's PATH
 * 
 * @author rayen
 *
 */
public class RequestExecutionFilter extends ZuulFilter {

	private static Logger log = LoggerFactory.getLogger(RequestExecutionFilter.class);
	private static final String CLIENT_ID = "client_id";
	private static final String CLIENT_SECRET = "client_secret";
	private static final String IDENTITYPROVIDER = "identityProvider";
	private static final String USERNAME = "username";
	private static final String PASSWORD = "password";

	@Autowired
	private APIService apiService;

	@Autowired
	private SecurityService securityFilter;

	@Autowired
	private SecurityAuthMS securityAuthMS;

	/**
	 * Filter Should run Before Forwarding the Request to the MicroService
	 */
	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}

	@Override
	public int filterOrder() {
		return FilterConstants.SEND_FORWARD_FILTER_ORDER;
	}

	@Override
	public boolean shouldFilter() {
		RequestContext context = RequestContext.getCurrentContext();
		HttpServletRequest request = context.getRequest();
		return !(request.getServletPath().startsWith("/api") || request.getServletPath().startsWith("/function")
		|| request.getServletPath().startsWith("/runtime/iam/oauth2") || request.getServletPath().startsWith("/runtime/frontRedirect"));
	}

	@Override
	@JsonIgnoreProperties(ignoreUnknown = true)
	public Object run() {
		String authorizedMessage = "authorized";
		log.debug("run method is EXECUTED");

		StopWatch stopWatch = new StopWatch();
		stopWatch.start("handle execution request");

		RequestContext context = RequestContext.getCurrentContext();
		HttpServletRequest request = context.getRequest();
		// Log Request
		log.debug("Request Recieved : Method {} with path {}", request, request.getServletPath());
		try {
			String requestType = request.getServletPath().substring(1,
					request.getServletPath().indexOf('/', request.getServletPath().indexOf('/') + 1));
			List<String> pathParts = new ArrayList<String>(
					Arrays.asList(request.getServletPath().substring(1).split("/")));
			if (requestType.equals("runtime") && pathParts.size() == 2) {
				forwardHealthCheck(context, pathParts.get(1));
			}

			if (request.getServletPath().indexOf("/runtime/logs") == 0) {
				forwaredLogRequest(context, request.getServletPath());
			} else if (request.getServletPath().indexOf("/runtime/static") == 0
					|| request.getServletPath().indexOf("/runtime/cache") == 0) {
				forwardStaticResource(context, request.getServletPath());
			} else if (requestType.equals("runtime") && pathParts.size() > 2) {
				// Transformation API
				String containerId = request.getServletPath().substring(requestType.length() + 2).substring(0,
						request.getServletPath().substring(requestType.length() + 2).indexOf('/', 0));
				String resourcePath = request.getServletPath()
						.substring(requestType.length() + containerId.length() + 2);
				StopWatch watchResource = new StopWatch();
				watchResource.start("watch resource");
				log.info("forwarded from {}", request.getHeader("Host"));
				log.info("forwarded url from {}", request.getRequestURL());
				log.info("forwarded uri from {}", request.getRequestURI());
				RuntimeResource resource = apiService.getResource(containerId, resourcePath, request.getMethod(), request.getHeader("accept"));
				watchResource.stop();
				log.info("Resource {}", resource);
				// if (resource == null) {
				// resource = createReourceOnTheFly(containerId, resource, authorizedMessage,
				// context, resourcePath);
				// }
				try {
					if (resource.getPath() != null) {

						if (resource.getServiceURL() != null) {

							authorizedMessage = checkTokenValidation(request, resource, containerId);

							if (authorizedMessage.equals("authorized")) {
								if (resource.getExecutionType() != null
										&& (resource.getExecutionType().equalsIgnoreCase("Query")
												|| resource.getExecutionType().equalsIgnoreCase("FILE"))) {
									forwardDBQuery(request, resource, context, containerId, resourcePath);
								}
							} else {
								forwardSecurityError(context, authorizedMessage, "401");
							}
						} else {
							// Check if API secured
							if (resource.getCustomQuery().getCollectionName() != null
									|| resource.getCurrentMicroservicetype().equals("authentication microservice")
									|| (resource.getFunctions() != null && !resource.getFunctions().isEmpty())
									|| resource.getExecutionType().equals("File")) {
										authorizedMessage = checkTokenValidation(request, resource, containerId);

								if (authorizedMessage.equals("authorized")) {
									if (resource.getExecutionType() != null
											&& (resource.getExecutionType().equalsIgnoreCase("Query")
													|| resource.getExecutionType().equalsIgnoreCase("FILE"))) {
										StopWatch queryHandlingWatch = new StopWatch();
										queryHandlingWatch.start();
										forwardDBQuery(request, resource, context, containerId, resourcePath);
										queryHandlingWatch.stop();

									} else {
										forwardTransformationQuery(resource, context, containerId, resourcePath);
									}
								} else {
									forwardSecurityError(context, authorizedMessage, "401");
								}
							} else {
								authorizedMessage = "You must provide a collection name";
								forwardSecurityError(context, authorizedMessage, "400");
							}
						}

					} else {
						authorizedMessage = "This API URL is not valid or no longer exists.";
						forwardSecurityError(context, authorizedMessage, "404");

					}
				} catch (Exception e) {
					log.info("message {}", e.getMessage());
				}
			}
		} catch (RuntimeException e) {
			log.error("Url malformed", e);
			forwardSecurityError(context, authorizedMessage, "400");
		}
		stopWatch.stop();
		return null;
	}

	private String checkTokenValidation(HttpServletRequest request, RuntimeResource resource, String containerId) throws UnsupportedEncodingException {
		String key = resource.getSecurityKey();
		String runtimeUrl = resource.getAuthMSRuntimeUrl();
		List<String> securityLevel = resource.getSecurityLevel();
		String authMsg = "authorized";
		log.info("authms runtime url" + resource.getAuthMSRuntimeUrl());
		if (!securityLevel.contains("public")) {
			String token = request.getHeader("Authorization");
			if (securityAuthMS.isdelegatedSecurityToAuthMicroservice(runtimeUrl)) {
				RSAPublicKey pk = securityAuthMS.getPublicKey(resource);
				authMsg = securityFilter.validateToken(token, null, securityLevel, pk);
			} else {
				authMsg = securityFilter.validateToken(token, key, securityLevel, null);
			}
		}
		return authMsg;
	}

	private RuntimeResource createReourceOnTheFly(String containerId, RuntimeResource resource,
			String authorizedMessage, RequestContext context, String resourcePath) throws IOException {
		List<String> parameterNames = new ArrayList<String>();
		while (context.getRequest().getParameterNames().hasMoreElements()) {
			String parameterName = context.getRequest().getParameterNames().nextElement();
			parameterNames.add(parameterName);
		}
		if (context.getRequest().getHeader("query") != null) {
			parameterNames.add(context.getRequest().getHeader("query"));
		}
		if (context.getRequest().getHeader("apikey") != null) {
			if (apiService.getUserByApiKey(context.getRequest().getHeader("apikey"), containerId)) {
				CreateResourceRequest createresource = new CreateResourceRequest();
				createresource.setParsedBody(new HttpServletRequestWrapper(context.getRequest()).getReader().lines()
						.reduce("", (accumulator, actual) -> accumulator + actual));
				createresource.setPath(resourcePath);
				createresource.setRequestparam(parameterNames);
				createresource.setHttpMethod(context.getRequest().getMethod());
				try {
					apiService.createResource(containerId, createresource);
					resource = apiService.getResource(containerId, resourcePath, context.getRequest().getMethod(), context.getRequest().getHeader("accept"));
					return resource;
				} catch (Exception e) {
					log.info(e.getMessage());
					authorizedMessage = "url mal formed";
				}
			} else {
				authorizedMessage = "INVALID API KEY OR CONTAINER ID";
				forwardSecurityError(context, authorizedMessage, "401");
			}
		} else {
			authorizedMessage = "YOU NEED TO PROVIDE AN API KEY";
			forwardSecurityError(context, authorizedMessage, "401");
		}
		return null;
	}

	private void forwardSecurityError(RequestContext context, String authorizedMessage, String code) {
		HttpServletRequest request = context.getRequest();
		HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request);

		context.addZuulRequestHeader("code", code);
		context.addZuulRequestHeader("authorizedMessage", authorizedMessage);
		context.put(REQUEST_URI_KEY, "/runtime/error");
		context.setRequest(wrapper);

	}

	private void forwardHealthCheck(RequestContext context, String containerId) {
		JSONObject jsonObject = new JSONObject(apiService.getHealthCheck(containerId));
		context.setResponseBody(jsonObject.toString(4));
	}

	public String convertWithStream(Map<?, ?> map) {
		String mapAsString = map.keySet().stream().map(key -> key + "=" + map.get(key))
				.collect(Collectors.joining(", ", "{", "}"));
		return mapAsString;
	}

	public String formatJson(String content) {
		return content.replace("\r\n", "").replace("\n", "").replace("  ", "").replace(" : ", ":").replace("[ {", "[{")
				.replace("} ]", "}]").replace(":[ ", ":[").replace(" ],", "],").replace("}, {", "},{")
				.replace(", ", ",").replace("\\\\", "");
	}

	private void forwardStaticResource(RequestContext context, String path) {
		HttpServletRequest request = context.getRequest();
		HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request);
		context.put(REQUEST_URI_KEY, path);
		context.setRequest(wrapper);
	}

	private void forwaredLogRequest(RequestContext context, String path) {
		HttpServletRequest request = context.getRequest();
		HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request);
		context.put(REQUEST_URI_KEY, path);
		context.setRequest(wrapper);

	}

	private void setParsedQuery(HttpServletRequestWrapper wrapper, JSONObject queryJson) {
		if (wrapper.getParameter(CLIENT_ID) != null) {
			queryJson.put(CLIENT_ID, wrapper.getParameter(CLIENT_ID));
		}
		if (wrapper.getParameter(CLIENT_SECRET) != null) {
			queryJson.put(CLIENT_SECRET, wrapper.getParameter(CLIENT_SECRET));
		}
		if (wrapper.getParameter(IDENTITYPROVIDER) != null) {
			queryJson.put(IDENTITYPROVIDER, wrapper.getParameter(IDENTITYPROVIDER));
		}
		if (wrapper.getParameter(USERNAME) != null) {
			queryJson.put(USERNAME, wrapper.getParameter(USERNAME));
		}
		if (wrapper.getParameter(PASSWORD) != null) {
			queryJson.put(PASSWORD, wrapper.getParameter(PASSWORD));
		}
		if(wrapper.getParameter("redirect_uri") != null) {
			queryJson.put("redirect_uri", wrapper.getParameter("redirect_uri"));
		}
	}

	private void forwardDBQuery(HttpServletRequest req, RuntimeResource resource, RequestContext context,
			String containerId, String resourcePath) throws IOException {
		log.info("forward db query");
		HttpServletRequest request = context.getRequest();

		HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request);
		context.put(REQUEST_URI_KEY, "/runtime/query/" + containerId.toLowerCase() + '/' + resourcePath);

		RuntimeQueryRequest runtimeRequest = apiService.getRuntimeQueryRequest(resource);
		runtimeRequest.setParsedQuery(new HttpServletRequestWrapper(request).getReader().lines().reduce("",
				(accumulator, actual) -> accumulator + actual));
		// ADD USERNAME TO RUNTIME REQUEST

		runtimeRequest.setCurrentMicroservicetype(resource.getCurrentMicroservicetype());
		if (resource.getCurrentMicroservicetype().equals("authentication microservice")) {
			JSONObject queryJson = new JSONObject();
			context.addZuulRequestHeader("authMSRuntimeUrl", resource.getAuthMSRuntimeUrl());
			setParsedQuery(wrapper, queryJson);

			runtimeRequest.setParsedQuery(queryJson.toString());
	
		}
		String authToken = request.getHeader("Authorization");
		if (!resource.getSecurityLevel().contains("public") && StringUtils.isNotBlank(authToken)) {
			Claims claims;
			if (securityAuthMS.isdelegatedSecurityToAuthMicroservice(resource.getAuthMSRuntimeUrl())) {
				RSAPublicKey pk = securityAuthMS.getPublicKey(resource);
				claims = SecurityService.parseRSAClaims(authToken, pk);
			} else {
				claims = SecurityService.parseClaims(authToken, resource.getSecurityKey());
			}
			runtimeRequest.setUsername(claims.getSubject());
		}
		try {
			if (req.getHeader("query") != null) {
				context.addZuulRequestHeader("q", req.getHeader("query"));
			}
			context.addZuulRequestHeader("query", new ObjectMapper().writeValueAsString(runtimeRequest));
			if (resource.getCurrentMicroservicetype().equals("authentication microservice") && resourcePath.equals("/userinfo")) {
				String authTokenValue = StringUtils.removeStart(authToken, "Bearer ");
				context.addZuulRequestHeader("token", authTokenValue);
			}
		} catch (JsonProcessingException e) {
			log.debug("An error has been occured while parsing object {}", e.getMessage());
		}
		context.setRequest(wrapper);
		/**
		 * Add the Received Runtime Request to the Request Body
		 */

	}

	private void forwardTransformationQuery(RuntimeResource resource, RequestContext context, String containerId,
			String resourcePath) {

		HttpServletRequest request = context.getRequest();
		HttpServletRequestWrapper wrapper = new HttpServletRequestWrapper(request);

		context.setRequest(wrapper);
		/**
		 * Get the Runtime Request from the API Manager
		 */
		RuntimeRequest<?> runtimeRequest = apiService.getRuntimeRequest(containerId, resource);
		context.put(REQUEST_URI_KEY, "/runtime/" + runtimeRequest.getExecutionType().toLowerCase());
		/**
		 * Add the Received Runtime Request to the Request Body
		 */
		try {
			InputStream in = (InputStream) context.get("requestEntity");
			if (in == null) {
				in = context.getRequest().getInputStream();
			}
			String body = StreamUtils.copyToString(in, Charset.forName(StandardCharsets.UTF_8.toString()));
			body = new ObjectMapper().writeValueAsString(runtimeRequest) + body;
			byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
			/**
			 * Build a new HttpServletRequest
			 */
			context.setRequest(apiService.makeHttpServletRequest(request, bytes));
		} catch (Exception e) {
			log.error(e.getMessage());
		}
	}

	public String getType(String value) {
		String result = "string";
		if (BooleanUtils.toBooleanObject(value) != null) {
			result = "boolean";
		} else if (NumberUtils.isNumber(value)) {
			result = "number";
		}
		return result;
	}
}
