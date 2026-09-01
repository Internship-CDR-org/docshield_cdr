package model.common;

import java.util.LinkedHashMap;
import java.util.Map;

public class MetadataModel {

    private Map<String, String> coreMetadata;
    private Map<String, String> applicationMetadata;
    private Map<String, String> customMetadata;

    public MetadataModel() {
        coreMetadata = new LinkedHashMap<>();
        applicationMetadata = new LinkedHashMap<>();
        customMetadata = new LinkedHashMap<>();
    }

    public Map<String, String> getCoreMetadata() {
        return coreMetadata;
    }
    public Map<String, String> getApplicationMetadata() {
        return applicationMetadata;
    }
    public Map<String, String> getCustomMetadata() {
        return customMetadata;
    }

    public void addCoreMetadata(String key,String value) {
        coreMetadata.put(key, value);
    }
    public void addApplicationMetadata(String key,String value) {
        applicationMetadata.put(key, value);
    }
    public void addCustomMetadata(String key,String value) {
        customMetadata.put(key, value);
    }
}