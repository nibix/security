/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.privileges;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.ImmutableSet;

import org.opensearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.opensearch.security.resolver.IndexResolverReplacer.Resolved;
import org.opensearch.security.securityconf.EvaluatedDlsFlsConfig;

import com.selectivem.check.CheckTable;

public class PrivilegesEvaluatorResponse {
    boolean allowed = false;
    Set<String> missingSecurityRoles = new HashSet<>();
    Set<String> resolvedSecurityRoles = new HashSet<>();
    EvaluatedDlsFlsConfig evaluatedDlsFlsConfig;
    PrivilegesEvaluatorResponseState state = PrivilegesEvaluatorResponseState.PENDING;
    Resolved resolved;
    CreateIndexRequestBuilder createIndexRequestBuilder;
    private Set<String> onlyAllowedForIndices = ImmutableSet.of();
    private CheckTable<String, String> indexToActionCheckTable;
    private String reason;

    public Resolved getResolved() {
        return resolved;
    }

    /**
     * Returns true if the request can be fully allowed. See also isAllowedForSpecificIndices().
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * Returns true if the request can be allowed if the referenced indices are reduced (aka "do not fail on forbidden")
     */
    public boolean isPartiallyOk() {
        return !this.onlyAllowedForIndices.isEmpty();
    }

    public Set<String> getAvailableIndices() {
        return this.onlyAllowedForIndices;
    }

    public Set<String> getMissingPrivileges() {
        return this.indexToActionCheckTable != null ? this.indexToActionCheckTable.getIncompleteColumns() : Collections.emptySet();
    }

    public String getReason() {
        return this.reason;
    }

    public PrivilegesEvaluatorResponse reason(String reason) {
        this.reason = reason;
        return this;
    }

    public CheckTable<String, String> getCheckTable() {
        return indexToActionCheckTable;
    }

    public Set<String> getMissingSecurityRoles() {
        return new HashSet<>(missingSecurityRoles);
    }

    public Set<String> getResolvedSecurityRoles() {
        return new HashSet<>(resolvedSecurityRoles);
    }

    public EvaluatedDlsFlsConfig getEvaluatedDlsFlsConfig() {
        return evaluatedDlsFlsConfig;
    }

    public CreateIndexRequestBuilder getCreateIndexRequestBuilder() {
        return createIndexRequestBuilder;
    }

    public PrivilegesEvaluatorResponse markComplete() {
        this.state = PrivilegesEvaluatorResponseState.COMPLETE;
        return this;
    }

    public PrivilegesEvaluatorResponse markPending() {
        this.state = PrivilegesEvaluatorResponseState.PENDING;
        return this;
    }

    public boolean isComplete() {
        return this.state == PrivilegesEvaluatorResponseState.COMPLETE;
    }

    public boolean isPending() {
        return this.state == PrivilegesEvaluatorResponseState.PENDING;
    }

    @Override
    public String toString() {
        return "PrivEvalResponse [\nallowed="
            + allowed
            + ",\nonlyAllowedForIndices="
            + onlyAllowedForIndices
            + ",\n"
            + (indexToActionCheckTable != null ? indexToActionCheckTable.toTableString("ok", "MISSING") : "")
            + ",\nevaluatedDlsFlsConfig="
            + evaluatedDlsFlsConfig
            + "]";
    }

    public static PrivilegesEvaluatorResponse ok() {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.allowed = true;
        return response;
    }

    public static PrivilegesEvaluatorResponse partiallyOk(
        Set<String> availableIndices,
        CheckTable<String, String> indexToActionCheckTable,
        PrivilegesEvaluationContext context
    ) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.onlyAllowedForIndices = ImmutableSet.copyOf(availableIndices);
        response.indexToActionCheckTable = indexToActionCheckTable;
        response.resolvedSecurityRoles.addAll(context.getMappedRoles());
        return response;
    }

    public static PrivilegesEvaluatorResponse insufficient(String missingPrivilege, PrivilegesEvaluationContext context) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.indexToActionCheckTable = CheckTable.create(ImmutableSet.of("_"), ImmutableSet.of(missingPrivilege));
        response.resolvedSecurityRoles.addAll(context.getMappedRoles());
        return response;
    }

    public static PrivilegesEvaluatorResponse insufficient(
        CheckTable<String, String> indexToActionCheckTable,
        PrivilegesEvaluationContext context
    ) {
        PrivilegesEvaluatorResponse response = new PrivilegesEvaluatorResponse();
        response.indexToActionCheckTable = indexToActionCheckTable;
        response.resolvedSecurityRoles.addAll(context.getMappedRoles());
        return response;
    }

    public static enum PrivilegesEvaluatorResponseState {
        PENDING,
        COMPLETE;
    }

}
