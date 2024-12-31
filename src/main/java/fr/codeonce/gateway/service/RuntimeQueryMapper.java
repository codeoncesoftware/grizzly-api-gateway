package fr.codeonce.gateway.service;

import fr.codeonce.grizzly.common.runtime.RuntimeQueryRequest;
import fr.codeonce.grizzly.common.runtime.RuntimeRequest;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResource;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResourceFile;
import fr.codeonce.grizzly.common.runtime.resource.RuntimeResourceParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.stream.Collectors;

@SuppressWarnings("deprecation")
public class RuntimeQueryMapper {

    private RuntimeQueryMapper() {

    }

    private static final Logger log = LoggerFactory.getLogger(RuntimeQueryMapper.class);

    public static RuntimeQueryRequest mapToRuntimeQueryRequest(RuntimeResource resource) {
        if (resource == null) {
            return null;
        }
        RuntimeQueryRequest request = new RuntimeQueryRequest();
        request.setHttpMethod(resource.getHttpMethod());
        request.setPath(resource.getPath());
        request.setFunctions(resource.getFunctions());
        request.setHost(resource.getHost());
        request.setExecutionType(resource.getExecutionType());
        request.setQueryType(resource.getCustomQuery().getType());
        request.setQuery(resource.getCustomQuery().getQuery());
        request.setRequestModels(resource.getRequestModels());
        request.setOutFunctions(resource.getOutFunctions());
        request.setInFunctions(resource.getInFunctions());
        request.setResponses(resource.getResponses());
        request.setSecurityLevel(resource.getSecurityLevel());
        request.setPageable(resource.isPageable());
        request.setDbsourceId(resource.getCustomQuery().getDatasource());
        request.setConnectionMode(resource.getConnectionMode());
        request.setDatabaseName(resource.getCustomQuery().getDatabase());
        request.setPhysicalDatabaseName(resource.getPhysicalDatabase());
        request.setCollectionName(resource.getCustomQuery().getCollectionName());
        request.setMany(resource.getCustomQuery().isMany());
        request.setParameters(resource.getParameters());
        request.setReturnType(resource.getReturnType());
        request.setProvider(resource.getProvider());
        request.setFields(resource.getFields());
        request.setBucketName(resource.getBucketName());
        request.setIndexType(resource.getCustomQuery().getIndexType());
        request.setServiceURL(resource.getServiceURL());
        request.setMapping(resource.getMapping());
        request.setResourceLog(resource.getResourceLog());
        request.setDatabaseType(resource.getDatabaseType());
        request.setExistedIdentityProvidersName(resource.getExistedIdentityProvidersName());
        request.setAuthorizedApps(resource.getAuthorizedApps());
        request.setCurrentMicroservicetype(resource.getCurrentMicroservicetype());
        request.setQueryName(resource.getCustomQuery().getQueryName());
        return request;
    }

    public static RuntimeRequest<String> getRuntimeTransformationEquest(RuntimeResource resource, String containerId) {
        if (resource == null) {
            return null;
        }
        RuntimeRequest<String> runtimeRequest = new RuntimeRequest<>();
        runtimeRequest.setExecutablePath(resource.getResourceFile().getFileUri());
        Optional<RuntimeResourceParameter> parameter = resource.getParameters().stream()
                .filter(param -> param.getName().equalsIgnoreCase("body")).findFirst();
        if (parameter.isPresent()) {
            runtimeRequest.setBody(parameter.get().getValue());
        }
        runtimeRequest.setExecutionType(resource.getExecutionType());
        runtimeRequest.setContainerId(containerId);
        runtimeRequest.setSecondaryFilePaths(resource.getSecondaryFilePaths().stream()
                .map(RuntimeResourceFile::getFileUri).collect(Collectors.toList()));
        return runtimeRequest;
    }
}
