/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.privileges.legacy;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.RestLayerPrivilegesEvaluator;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.SecurityRoles;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import org.greenrobot.eventbus.Subscribe;

public class RestLayerPrivilegesEvaluatorImpl implements RestLayerPrivilegesEvaluator {
    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ClusterService clusterService;
    private ThreadContext threadContext;
    private ConfigModel configModel;

    public RestLayerPrivilegesEvaluatorImpl(final ClusterService clusterService, final ThreadPool threadPool) {
        this.clusterService = clusterService;
        this.threadContext = threadPool.getThreadContext();
    }

    @Subscribe
    public void onConfigModelChanged(final ConfigModel configModel) {
        this.configModel = configModel;
    }

    SecurityRoles getSecurityRoles(final Set<String> roles) {
        return configModel.getSecurityRoles().filter(roles);
    }

    boolean isInitialized() {
        return configModel != null && configModel.getSecurityRoles() != null;
    }

    public PrivilegesEvaluatorResponse evaluate(final User user, String routeName, final Set<String> actions) {
        if (!isInitialized()) {
            throw new OpenSearchSecurityException("OpenSearch Security is not initialized.");
        }

        final PrivilegesEvaluatorResponse presponse = new PrivilegesEvaluatorResponse();

        final TransportAddress caller = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);

        final Set<String> mappedRoles = mapRoles(user, caller);

        final SecurityRoles securityRoles = getSecurityRoles(mappedRoles);

        final boolean isDebugEnabled = log.isDebugEnabled();
        if (isDebugEnabled) {
            log.debug("Evaluate permissions for {} on {}", user, clusterService.localNode().getName());
            log.debug("Action: {}", actions);
            log.debug("Mapped roles: {}", mappedRoles.toString());
        }

        for (final String action : actions) {
            if (!securityRoles.impliesClusterPermissionPermission(action)) {
                presponse.allowed = false;
                log.info(
                    "No permission match for {} [Action [{}]] [RolesChecked {}]. No permissions for {}",
                    user,
                    action,
                    securityRoles.getRoleNames(),
                    action
                );
            } else {
                if (isDebugEnabled) {
                    log.debug("Allowed because we have permissions for {}", actions);
                }
                presponse.allowed = true;

                // break the loop as we found the matching permission
                break;
            }
        }

        if (presponse.allowed) {
            return PrivilegesEvaluatorResponse.ok();
        } else {
            return PrivilegesEvaluatorResponse.insufficient(actions);
        }
    }

    Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }
}