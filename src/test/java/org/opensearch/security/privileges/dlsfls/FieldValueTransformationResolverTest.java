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

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.junit.Test;
import org.bouncycastle.util.encoders.Hex;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.mapper.FieldValueTransformation;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FieldValueTransformationResolverTest {
    // Identical vectors are used in the test at
    // OpenSearch/sandbox/plugins/analytics-backend-datafusion/rust/src/masking.rs.
    private static final List<GoldenVector> GOLDEN_VECTORS = List.of(
        new GoldenVector(
            "blake2b-256-personalized-ascii",
            "BLAKE2B_256_PERSONALIZED",
            "30313233343536373839616263646566",
            "alice",
            "4ea22c69e3064517f269cfe53906f6492e99f19337b3ce659f1c49f5af3c5d34",
            List.of()
        ),
        new GoldenVector(
            "blake2b-256-salted-unicode",
            "BLAKE2B_256_SALTED",
            "30313233343536373839616263646566",
            "Grüße 東京",
            "8353eae0d97a4b105e7c2af5735d8bb84a85d07498fb4681fd139c56b84a2472",
            List.of()
        ),
        new GoldenVector(
            "sha-256-ascii",
            "SHA_256",
            "",
            "alice",
            "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90",
            List.of()
        ),
        new GoldenVector(
            "sha-512-unicode",
            "SHA_512",
            "",
            "Grüße 東京",
            "04d2411562af0ca5edeab8e6a44d9ce53ffc44fed60242e7f797f62e4abab3f9e0f2adf6a36627f5021d6b3662b6be79f5452cbcc4d865685903e949589bdd71",
            List.of()
        ),
        new GoldenVector(
            "regex-captures-and-sequential-replacement",
            null,
            "",
            "alice-7",
            "id=alice",
            List.of(new RegexVector("^([a-z]+)-([0-9]+)$", "$2:$1"), new RegexVector("^7:", "id="))
        )
    );

    @Test
    public void resolvesEffectiveFieldMaskingRule() throws Exception {
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        FieldMasking fieldMasking = mock(FieldMasking.class);
        FieldMasking.FieldMaskingRule rule = FieldMasking.FieldMaskingRule.of(FieldMasking.Config.DEFAULT, "secret::SHA-256");
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getFieldMasking()).thenReturn(fieldMasking);
        when(fieldMasking.getRestriction(context, "logs-000001")).thenReturn(rule);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.getPrivilegesEvaluationContext()).thenReturn(context);
        when(baseContext.config()).thenReturn(config);

        Optional<FieldValueTransformation> transformation = new FieldValueTransformationResolver(baseContext).forIndex("logs-000001")
            .resolve("secret");

        assertThat(transformation.orElseThrow(), instanceOf(FieldValueTransformation.Hash.class));
        assertThat(
            ((FieldValueTransformation.Hash) transformation.orElseThrow()).algorithm(),
            is(FieldValueTransformation.HashAlgorithm.SHA_256)
        );
        assertThat(new FieldValueTransformationResolver(baseContext).forIndex("logs-000001").resolve("visible").stream().toList(), empty());
    }

    @Test
    public void returnsNoTransformationForSystemContext() {
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);

        assertThat(new FieldValueTransformationResolver(baseContext).forIndex("logs").resolve("secret").stream().toList(), empty());
    }

    @Test
    public void failsClosedWhenPrivilegeEvaluationFails() throws Exception {
        PrivilegesEvaluationContext context = mock(PrivilegesEvaluationContext.class);
        FieldMasking fieldMasking = mock(FieldMasking.class);
        when(fieldMasking.getRestriction(context, "logs")).thenThrow(
            new PrivilegesEvaluationException("test evaluation failure", new IllegalStateException("cause"))
        );
        DlsFlsProcessedConfig config = mock(DlsFlsProcessedConfig.class);
        when(config.getFieldMasking()).thenReturn(fieldMasking);
        DlsFlsBaseContext baseContext = mock(DlsFlsBaseContext.class);
        when(baseContext.getPrivilegesEvaluationContext()).thenReturn(context);
        when(baseContext.config()).thenReturn(config);

        OpenSearchSecurityException exception = assertThrows(
            OpenSearchSecurityException.class,
            () -> new FieldValueTransformationResolver(baseContext).forIndex("logs").resolve("secret")
        );

        assertThat(exception.getMessage(), containsString("index [logs] and field [secret]"));
    }

    @Test
    public void rejectsUnsupportedAlgorithmAndRegexSubset() throws Exception {
        FieldMasking.FieldMaskingRule.Field md5 = field("secret::MD5", Settings.EMPTY);
        IllegalArgumentException algorithm = assertThrows(IllegalArgumentException.class, md5::toFieldValueTransformation);
        assertThat(algorithm.getMessage(), containsString("algorithm [MD5] is not supported for pluggable data formats"));

        FieldMasking.FieldMaskingRule.Field lookahead = field("secret::/(?=alice)/::masked", Settings.EMPTY);
        IllegalArgumentException regex = assertThrows(IllegalArgumentException.class, lookahead::toFieldValueTransformation);
        assertThat(regex.getMessage(), containsString("uses unsupported construct [(?=]"));
    }

    @Test
    public void javaMaskingMatchesSharedGoldenVectors() throws Exception {
        for (GoldenVector vector : GOLDEN_VECTORS) {
            FieldMasking.FieldMaskingRule.Field field;
            if (vector.replacements().isEmpty() == false) {
                StringBuilder source = new StringBuilder("secret");
                for (RegexVector replacement : vector.replacements()) {
                    source.append("::/").append(replacement.pattern()).append("/::").append(replacement.replacement());
                }
                field = field(source.toString(), Settings.EMPTY);
            } else {
                String algorithm = vector.algorithm();
                Settings.Builder settings = Settings.builder();
                if (vector.parameterHex().isEmpty() == false) {
                    settings.put("plugins.security.compliance.salt", new String(Hex.decode(vector.parameterHex()), StandardCharsets.UTF_8));
                }
                String expression = "secret";
                if ("BLAKE2B_256_PERSONALIZED".equals(algorithm)) {
                    settings.put("plugins.security.masked_fields.algorithm.default", FieldMasking.Config.BLAKE2B_LEGACY_DEFAULT);
                } else if ("SHA_256".equals(algorithm)) {
                    expression += "::SHA-256";
                } else if ("SHA_512".equals(algorithm)) {
                    expression += "::SHA-512";
                }
                field = field(expression, settings.build());
            }

            assertThat(vector.name(), field.apply(vector.input()), is(vector.expected()));
            assertDescriptorMatches(vector, field.toFieldValueTransformation());
        }
    }

    private static FieldMasking.FieldMaskingRule.Field field(String expression, Settings settings) throws Exception {
        return new FieldMasking.FieldMaskingRule.Field(
            new FieldMasking.FieldMaskingExpression(expression),
            FieldMasking.Config.fromSettings(settings)
        );
    }

    private static void assertDescriptorMatches(GoldenVector vector, FieldValueTransformation transformation) {
        if (vector.replacements().isEmpty() == false) {
            assertThat(transformation, instanceOf(FieldValueTransformation.RegexReplace.class));
            assertThat(((FieldValueTransformation.RegexReplace) transformation).replacements().size(), is(vector.replacements().size()));
            return;
        }

        FieldValueTransformation.Hash hash = (FieldValueTransformation.Hash) transformation;
        assertThat(hash.algorithm().name(), is(vector.algorithm()));
        assertArrayEquals(Hex.decode(vector.parameterHex()), hash.salt());
    }

    private record GoldenVector(String name, String algorithm, String parameterHex, String input, String expected, List<
        RegexVector> replacements) {
    }

    private record RegexVector(String pattern, String replacement) {
    }
}
