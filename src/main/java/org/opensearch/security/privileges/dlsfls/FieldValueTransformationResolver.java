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

import java.util.Optional;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.index.mapper.FieldValueTransformation;
import org.opensearch.plugins.FieldValueTransformationProvider;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;

/** Resolves the effective Security field-masking rule for a concrete index and mapped leaf. */
public final class FieldValueTransformationResolver implements FieldValueTransformationProvider {

    private final DlsFlsBaseContext baseContext;

    public FieldValueTransformationResolver(DlsFlsBaseContext baseContext) {
        this.baseContext = baseContext;
    }

    @Override
    public FieldTransformations forIndex(String concreteIndex) {
        return field -> resolve(concreteIndex, field);
    }

    private Optional<FieldValueTransformation> resolve(String concreteIndex, String field) {
        PrivilegesEvaluationContext context = baseContext.getPrivilegesEvaluationContext();
        if (context == null) {
            return Optional.empty();
        }

        try {
            FieldMasking.FieldMaskingRule rule = baseContext.config().getFieldMasking().getRestriction(context, concreteIndex);
            FieldMasking.FieldMaskingRule.Field transformation = rule.get(field);
            return transformation == null ? Optional.empty() : Optional.of(transformation.toFieldValueTransformation());
        } catch (PrivilegesEvaluationException e) {
            throw new OpenSearchSecurityException(
                "Unable to determine field masking policy for index [" + concreteIndex + "] and field [" + field + "]",
                e
            );
        }
    }
}
