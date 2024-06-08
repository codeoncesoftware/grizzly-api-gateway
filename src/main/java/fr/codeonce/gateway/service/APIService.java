package fr.codeonce.gateway.service;

import fr.codeonce.gateway.model.DBSource;
import fr.codeonce.grizzly.common.runtime.HealthCheck;
import fr.codeonce.grizzly.common.runtime.RuntimeQueryRequest;
import fr.codeonce.grizzly.common.runtime.RuntimeRequest;
import fr.codeonce.grizzly.common.runtime.resource.CreateResourceRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StopWatch;

@Service
public class APIService {

    @Autowired
    private FeignDiscovery feignDiscovery;

    private static Logger log = LoggerFactory.getLogger(APIService.class);

    /**
     * Prepare the Runtime Request from Resource Object
     *
     * @param authorization
     * @param containerId
     * @return the Runtime Request to be Forwarded to the MicroService
     */
    public RuntimeRequest<?> getRuntimeRequest(
            String containerId,
            RuntimeResource resource
    ) {
        return RuntimeQueryMapper.getRuntimeTransformationEquest(
                resource,
                containerId
        );
    }

    public RuntimeQueryRequest getRuntimeQueryRequest(RuntimeResource resource) {
        return RuntimeQueryMapper.mapToRuntimeQueryRequest(resource);
    }

    /**
     * Fetch a Resource From Database based on the Container Id and the Unique
     * Resource Path
     *
     * @param containerId
     * @param resourcePath
     * @return
     */

    public RuntimeResource getResource(
            String containerId,
            String resourcePath,
            String method,
            String returnType
    ) {
        try {
            StopWatch watch1 = new StopWatch();
            watch1.start("create Resource");
            RuntimeResource runtimeResource = feignDiscovery.getResource(
                    containerId,
                    resourcePath,
                    method,
                    returnType
            );
            watch1.stop();
            return runtimeResource;
        } catch (Exception e) {
            // e.printStackTrace();
            log.error(
                    "Cound not get the resource : container {} resourcePath {}, method {}",
                    containerId,
                    resourcePath,
                    method,
                    e
            );
            return null;
            // TODO Auto-generated catch block
        }
    }

    public RuntimeResource createResource(
            String containerId,
            CreateResourceRequest createresourcerequest
    ) {
        StopWatch watch1 = new StopWatch();
        watch1.start("create Resource");
        RuntimeResource runtimeResource = feignDiscovery.createResource(
                containerId,
                createresourcerequest
        );
        watch1.stop();
        log.info("timing create:{}", watch1.getTotalTimeMillis());
        return runtimeResource;
    }

    public HealthCheck getHealthCheck(String containerId) {
        return feignDiscovery.getHealthCheck(containerId);
    }

    public boolean getUserByApiKey(String apikey, String containerId) {
        StopWatch watch1 = new StopWatch();
        watch1.start("authenticated");
        boolean result = feignDiscovery.getUserByApiKey(apikey, containerId);
        watch1.stop();
        log.info("timing authenticated:{}", watch1.getTotalTimeMillis());
        return result;
    }

    public DBSource getDBSource(String dbsourceId) {
        return feignDiscovery.getDBSource(dbsourceId);
    }
    /**
     * Add the Received Runtime Request to the Request Body
     *
     * @param bytes,  the Body to be set in the new HttpServletRequest
     * @param context to get the old HttpServeletRequest
     * @return a new HttpServeletRequest with the Runtime Request in Body
     */

    // public HttpServletRequest makeHttpServletRequest(HttpServletRequest request, byte[] bytes) {
    // 	return new HttpServletRequestWrapper(request) {
    // 		@Override
    // 		public ServletInputStream getInputStream() throws IOException {
    // 			return new ServletInputStreamWrapper(bytes);
    // 		}

    // 		@Override
    // 		public int getContentLength() {
    // 			return bytes.length;
    // 		}

    // 		@Override
    // 		public long getContentLengthLong() {
    // 			return bytes.length;
    // 		}
    // 	};
    // }

}
