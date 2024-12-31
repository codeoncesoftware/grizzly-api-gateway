package fr.codeonce.gateway.service;

import fr.codeonce.gateway.model.DBSource;
import fr.codeonce.grizzly.common.runtime.HealthCheck;
import fr.codeonce.grizzly.common.runtime.resource.CreateResourceRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "grizzly-api-core", url = "${core-url}")
public interface FeignDiscovery {
    @GetMapping("/api/resource/public")
    public RuntimeResource getResource(
            @RequestParam("containerId") String containerId,
            @RequestParam("resourcePath") String resourcePath,
            @RequestParam("method") String method,
            @RequestParam("returnType") String returnType
    );

    @GetMapping("/api/dbsource/public")
    public DBSource getDBSource(@RequestParam("dbsourceId") String dbsourceId);

    @GetMapping("/api/analytics/healthCheck")
    public HealthCheck getHealthCheck(
            @RequestParam("containerId") String containerId
    );

    @PostMapping("/api/resource/public/resourceRequest")
    public RuntimeResource createResource(
            @RequestParam("containerId") String containerId,
            @RequestBody CreateResourceRequest createResourceRequest
    );

    @GetMapping("/api/auth/userapikey")
    public boolean getUserByApiKey(
            @RequestParam("apikey") String apikey,
            @RequestParam("containerId") String containerId
    );

    @GetMapping("/project/{id}")
    public String getogByProjectId(@PathVariable String id);
}
