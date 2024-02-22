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

import java.security.spec.RSAPublicKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;

import fr.codeonce.grizzly.common.runtime.RuntimeQueryRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import fr.codeonce.grizzly.gateway.service.APIService;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class SecurityAuthMS {

	private static Logger log = LoggerFactory.getLogger(SecurityAuthMS.class);

	@Value("${grizzly-api-runtime.ribbon.listOfServers}")
	private String runtimeUri;

	@Value("${grizzly.client_id}")
	private String grizzlyPredefinedClientId;

	@Value("${grizzly.client_secret}")
	private String grizzlyPredefinedClientSecret;

	@Autowired
	private APIService apiService;

	public Boolean isdelegatedSecurityToAuthMicroservice(String runtimeUrl) {
		Boolean delegatedAuthMS = false;
		if (runtimeUrl != null) {
			delegatedAuthMS = true;
		}
		return delegatedAuthMS;
	}

	public RSAPublicKey getPublicKey(RuntimeResource resource) {
		WebClient client = WebClient.create();
		String containerId = resource.getAuthMSRuntimeUrl().substring(resource.getAuthMSRuntimeUrl().lastIndexOf('/')+1);
		RuntimeResource jwkResource = apiService.getResource(containerId, "/jwk", "GET", "application/json");
		RuntimeQueryRequest runtimeRequest = apiService.getRuntimeQueryRequest(jwkResource);
		JSONObject queryJson = new JSONObject();

		if((resource.getPath().equals("/userinfo") || resource.isDefaultIdP()) && resource.getCurrentMicroservicetype().equals("authentication microservice")) {
			queryJson.put("client_id", grizzlyPredefinedClientId);
			queryJson.put("client_secret", grizzlyPredefinedClientSecret);	
		} else {
			queryJson.put("client_id", resource.getClientId());
			queryJson.put("client_secret", resource.getSecurityKey());	
		}

		runtimeRequest.setParsedQuery(queryJson.toString());

		net.minidev.json.JSONObject jwks = null;
		try {
			jwks = client.get()
					.uri(runtimeUri + "/runtime/query/" + containerId.toLowerCase() + "/jwk")
					.header("query",new ObjectMapper().writeValueAsString(runtimeRequest))
					.retrieve()
					.bodyToMono(net.minidev.json.JSONObject.class)
					.block();
		} catch (JsonProcessingException e1) {
		}
		RSAPublicKey publicKey = null;
		if (jwks != null) {
			try {
				BigInteger modulus = new BigInteger(1, new Base64URL(jwks.get("n").toString()).decode());
				BigInteger exponent = new BigInteger(1, new Base64URL(jwks.get("e").toString()).decode());
				final KeyFactory kf = KeyFactory.getInstance("RSA");
				publicKey = (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				log.info("public key generation exception");
			}
		}
		return publicKey;
	}
}
