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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.support.FieldValueTransformationPolicy;
import org.opensearch.index.mapper.FieldValueTransformation;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;

/** Resolves the effective Security field-masking rule for a concrete index and mapped leaf. */
public final class FieldValueTransformationResolver {

    private final DlsFlsBaseContext baseContext;

    public FieldValueTransformationResolver(DlsFlsBaseContext baseContext) {
        this.baseContext = baseContext;
    }

    public FieldValueTransformationPolicy forIndex(String concreteIndex) {
        PrivilegesEvaluationContext context = baseContext.getPrivilegesEvaluationContext();
        if (context == null) {
            return FieldValueTransformationPolicy.unrestricted();
        }

        try {
            FieldMasking.FieldMaskingRule rule = baseContext.config().getFieldMasking().getRestriction(context, concreteIndex);
            return new FieldValueTransformationPolicy() {
                @Override
                public FieldValueTransformation resolve(String mappedLeafField) {
                    FieldMasking.FieldMaskingRule.Field transformation = rule.get(mappedLeafField);
                    return transformation == null ? FieldValueTransformation.none() : transformation.toFieldValueTransformation();
                }

                @Override
                public Map<String, FieldValueTransformation> resolve(Collection<String> mappedLeafFields) {
                    Map<String, FieldValueTransformation> resolved = new HashMap<>();
                    for (String field : mappedLeafFields) {
                        FieldMasking.FieldMaskingRule.Field transformation = rule.get(field);
                        resolved.put(
                            field,
                            transformation == null ? FieldValueTransformation.none() : transformation.toFieldValueTransformation()
                        );
                    }
                    return Map.copyOf(resolved);
                }
            };
        } catch (PrivilegesEvaluationException e) {
            throw new OpenSearchSecurityException("Unable to determine field masking policy for index [" + concreteIndex + "]", e);
        }
    }
}
