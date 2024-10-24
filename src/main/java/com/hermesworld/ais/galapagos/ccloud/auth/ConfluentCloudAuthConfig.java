package com.hermesworld.ais.galapagos.ccloud.auth;

import lombok.Getter;
import lombok.Setter;

import java.util.Objects;

@Getter
@Setter
public class ConfluentCloudAuthConfig {

    private String environmentId;

    private String clusterId;

    private String clusterApiKey;

    private String clusterApiSecret;

    private String developerApiKeyValidity;

    private String organizationApiKey;

    private String organizationApiSecret;

    private Boolean serviceAccountIdCompatMode;

    public boolean isServiceAccountIdCompatMode() {
        // currently (Sep 2022), true should be default for Confluent!
        return Objects.requireNonNullElse(serviceAccountIdCompatMode, true);
    }

}
