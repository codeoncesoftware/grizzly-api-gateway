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
package fr.codeonce.grizzly.gateway.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import fr.codeonce.grizzly.common.runtime.HealthCheck;
import fr.codeonce.grizzly.common.runtime.resource.CreateResourceRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import fr.codeonce.grizzly.gateway.filter.model.DBSource;

@FeignClient(name = "grizzly-api-core", url = "${core-url}")
public interface FeignDiscovery {

	@GetMapping("/api/resource/public")
	public RuntimeResource getResource(@RequestParam("containerId") String containerId,
			@RequestParam("resourcePath") String resourcePath, @RequestParam("method") String method, @RequestParam("returnType") String returnType);

	@GetMapping("/api/dbsource/public")
	public DBSource getDBSource(@RequestParam("dbsourceId") String dbsourceId);

	@GetMapping("/api/analytics/healthCheck")
	public HealthCheck getHealthCheck(@RequestParam("containerId") String containerId);

	@PostMapping("/api/resource/public/resourceRequest")
	public RuntimeResource createResource(@RequestParam("containerId") String containerId,
			@RequestBody CreateResourceRequest createResourceRequest);

	@GetMapping("/api/auth/userapikey")
	public boolean getUserByApiKey(@RequestParam("apikey") String apikey,
			@RequestParam("containerId") String containerId);

	@GetMapping("/project/{id}")
	public String getogByProjectId(@PathVariable String id);

}