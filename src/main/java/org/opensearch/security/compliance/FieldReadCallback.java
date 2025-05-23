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

package org.opensearch.security.compliance;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.FieldInfo;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.support.XContentMapValues;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexService;
import org.opensearch.index.mapper.Uid;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.support.HeaderHelper;
import org.opensearch.security.support.JsonFlattener;
import org.opensearch.security.support.SourceFieldsContext;

//TODO  We need to deal with caching!!
//Currently we disable caching (and realtime requests) when FLS or DLS is applied
//Check if we can hook in into the caches

//stored fields are already done here

public final class FieldReadCallback {

    private static final Logger log = LogManager.getLogger(FieldReadCallback.class);
    // private final ThreadContext threadContext;
    // private final ClusterService clusterService;
    private final Index index;
    private final FieldMasking.FieldMaskingRule fmRule;
    private final AuditLog auditLog;
    private Function<Map<String, ?>, Map<String, Object>> filterFunction;
    private SourceFieldsContext sfc;
    private Doc doc;
    private final ShardId shardId;

    public FieldReadCallback(
        final ThreadContext threadContext,
        final IndexService indexService,
        final ClusterService clusterService,
        final AuditLog auditLog,
        final FieldMasking.FieldMaskingRule fmRule,
        ShardId shardId
    ) {
        super();
        // this.threadContext = Objects.requireNonNull(threadContext);
        // this.clusterService = Objects.requireNonNull(clusterService);
        this.index = Objects.requireNonNull(indexService).index();
        this.auditLog = auditLog;
        this.fmRule = fmRule;
        this.shardId = shardId;
        try {
            sfc = (SourceFieldsContext) HeaderHelper.deserializeSafeFromHeader(threadContext, "_opendistro_security_source_field_context");
            if (sfc != null && sfc.hasIncludesOrExcludes()) {
                if (log.isTraceEnabled()) {
                    log.trace("_opendistro_security_source_field_context: {}", sfc);
                }

                filterFunction = XContentMapValues.filter(sfc.getIncludes(), sfc.getExcludes());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot deserialize _opendistro_security_source_field_context because of {}", e.toString());
            }
        }
    }

    private boolean recordField(final String fieldName, boolean isStringField) {
        // We do not record fields in read history if they are masked.
        return !(isStringField && fmRule.isMasked(fieldName))
            && auditLog.getComplianceConfig().readHistoryEnabledForField(index.getName(), fieldName);
    }

    public void binaryFieldRead(final FieldInfo fieldInfo, byte[] fieldValue) {
        try {
            if (!recordField(fieldInfo.name, false) && !fieldInfo.name.equals("_source") && !fieldInfo.name.equals("_id")) {
                return;
            }

            if (fieldInfo.name.equals("_source")) {

                if (filterFunction != null) {
                    final Map<String, Object> filteredSource = filterFunction.apply(Utils.byteArrayToMutableJsonMap(fieldValue));
                    fieldValue = Utils.jsonMapToByteArray(filteredSource);
                }

                final Map<String, Object> filteredSource = JsonFlattener.flattenAsMap(new String(fieldValue, StandardCharsets.UTF_8));
                for (String k : filteredSource.keySet()) {
                    if (!recordField(k, filteredSource.get(k) instanceof String)) {
                        continue;
                    }
                    fieldRead0(k, filteredSource.get(k));
                }
            } else if (fieldInfo.name.equals("_id")) {
                fieldRead0(fieldInfo.name, Uid.decodeId(fieldValue));
            } else {
                fieldRead0(fieldInfo.name, new String(fieldValue, StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            log.error("Unexpected error reading binary field '{}' in index '{}'", fieldInfo.name, index.getName());
        }
    }

    public void stringFieldRead(final FieldInfo fieldInfo, final String fieldValue) {
        try {
            if (!recordField(fieldInfo.name, true)) {
                return;
            }
            fieldRead0(fieldInfo.name, fieldValue);
        } catch (Exception e) {
            log.error("Unexpected error reading string field '{}' in index '{}'", fieldInfo.name, index.getName());
        }
    }

    public void numericFieldRead(final FieldInfo fieldInfo, final Number fieldValue) {
        try {
            if (!recordField(fieldInfo.name, false)) {
                return;
            }
            fieldRead0(fieldInfo.name, fieldValue);
        } catch (Exception e) {
            log.error("Unexpected error reading numeric field '{}' in index '{}'", fieldInfo.name, index.getName());
        }
    }

    private void fieldRead0(final String fieldName, final Object fieldValue) {
        if (doc != null) {
            if (fieldName.equals("_id")) {
                doc.setId(fieldValue.toString());
            } else {
                doc.addField(new Field(fieldName, fieldValue));
            }
        } else {
            final String indexName = index.getName();
            if (fieldName.equals("_id")) {
                doc = new Doc(indexName, fieldValue.toString());
            } else {
                doc = new Doc(indexName, null);
                doc.addField(new Field(fieldName, fieldValue));
            }
        }
    }

    public void finished() {
        if (doc == null) {
            return;
        }
        try {
            Map<String, String> f = new HashMap<String, String>();
            for (Field fi : doc.fields) {
                f.put(fi.fieldName, String.valueOf(fi.fieldValue));
            }
            auditLog.logDocumentRead(doc.indexName, doc.id, shardId, f);
        } catch (Exception e) {
            log.error("Unexpected error finished compliance read entry {} in index '{}': {}", doc.id, index.getName(), e.toString(), e);
        } finally {
            doc = null;
            sfc = null;
        }
    }

    private class Doc {
        final String indexName;
        String id;
        final List<Field> fields = new ArrayList<Field>();

        public Doc(String indexName, String id) {
            super();
            this.indexName = indexName;
            this.id = id;
        }

        public void addField(Field f) {
            fields.add(f);
        }

        public void setId(String id) {
            this.id = id;
        }

        @Override
        public String toString() {
            return "Doc [indexName=" + indexName + ", id=" + id + ", fields=" + fields + "]";
        }
    }

    private class Field {
        final String fieldName;
        final Object fieldValue;

        public Field(String fieldName, Object fieldValue) {
            super();
            this.fieldName = fieldName;
            this.fieldValue = fieldValue;
        }

        @Override
        public String toString() {
            return "Field [fieldName=" + fieldName + ", fieldValue=" + fieldValue + "]";
        }
    }
}
