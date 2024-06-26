/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.ClassRule;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

public class DefaultConfigurationMultiNodeClusterUseClusterStateTests extends AbstractDefaultConfigurationTests {

    static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .nodeSettings(
            Map.of(
                "plugins.security.allow_default_init_securityindex",
                true,
                "plugins.security.allow_default_init_securityindex.use_cluster_state",
                true,
                "plugins.security.restapi.roles_enabled",
                List.of("user_admin__all_access")
            )
        )
        .defaultConfigurationInitDirectory(configurationFolder.toString())
        .loadConfigurationIntoIndex(false)
        .build();

    @AfterClass
    public static void cleanConfigurationDirectory() throws IOException {
        FileUtils.deleteDirectory(configurationFolder.toFile());
    }

    public DefaultConfigurationMultiNodeClusterUseClusterStateTests() {
        super(cluster);
    }

}
