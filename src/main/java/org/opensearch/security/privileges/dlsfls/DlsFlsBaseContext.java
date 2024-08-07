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
package org.opensearch.security.privileges.dlsfls;

import com.google.common.collect.ImmutableSet;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.indices.IndicesModule;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;

/**
 * Node global context data for DLS/FLS
 */
public class DlsFlsBaseContext {
    private final PrivilegesEvaluator privilegesEvaluator;
    private final ThreadContext threadContext;

    public DlsFlsBaseContext(PrivilegesEvaluator privilegesEvaluator, ThreadContext threadContext) {
        this.privilegesEvaluator = privilegesEvaluator;
        this.threadContext = threadContext;
    }

    /**
     * Returns the PrivilegesEvaluationContext for the current thread. Returns null if the current thread is not
     * associated with a user. This indicates a system action. In these cases, no privilege evaluation should be performed.
     */
    public PrivilegesEvaluationContext getPrivilegesEvaluationContext() {
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);

        if (user == null) {
            return null;
        }

        return this.privilegesEvaluator.createContext(user, null);
    }

    public boolean isDlsDoneOnFilterLevel() {
        if (threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE) != null) {
            return true;
        } else {
            return false;
        }
    }

    String getDoneDlsFilterLevelQuery() {
        return threadContext.getHeader(ConfigConstants.OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE);
    }

    /**
     * Meta fields like _id get always included, regardless of settings.
     */
    private static final ImmutableSet<String> META_FIELDS = ImmutableSet.<String>builder().addAll(IndicesModule.getBuiltInMetadataFields()).add("_primary_term").build();

    public static boolean isMetaField(String field) {
        return META_FIELDS.contains(field);
    }
}
