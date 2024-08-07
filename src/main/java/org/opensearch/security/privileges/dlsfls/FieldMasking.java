package org.opensearch.security.privileges.dlsfls;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;
import org.apache.lucene.util.BytesRef;
import org.bouncycastle.util.encoders.Hex;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.configuration.Salt;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import com.rfksystems.blake2b.Blake2b;

public class FieldMasking extends AbstractRuleBasedPrivileges<FieldMasking.FieldMaskingRule.SingleRole, FieldMasking.FieldMaskingRule> {

    private final FieldMasking.Config fieldMaskingConfig;

    public FieldMasking(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        FieldMasking.Config fieldMaskingConfig,
        Settings settings
    ) {
        super(roles, indexMetadata, (rolePermissions) -> roleToRule(rolePermissions, fieldMaskingConfig), settings);
        this.fieldMaskingConfig = fieldMaskingConfig;
    }

    static FieldMaskingRule.SingleRole roleToRule(RoleV7.Index rolePermissions, FieldMasking.Config fieldMaskingConfig)
        throws PrivilegesConfigurationValidationException {
        List<String> fmExpressions = rolePermissions.getMasked_fields();

        if (fmExpressions != null && !fmExpressions.isEmpty()) {
            return new FieldMaskingRule.SingleRole(rolePermissions, fieldMaskingConfig);
        } else {
            return null;
        }
    }

    @Override
    protected FieldMaskingRule unrestricted() {
        return FieldMaskingRule.ALLOW_ALL;
    }

    @Override
    protected FieldMaskingRule fullyRestricted() {
        return new FieldMaskingRule.SingleRole(
            ImmutableList.of(new FieldMaskingRule.Field(FieldMaskingExpression.MASK_ALL, fieldMaskingConfig))
        );
    }

    @Override
    protected FieldMaskingRule compile(PrivilegesEvaluationContext context, Collection<FieldMaskingRule.SingleRole> rules)
        throws PrivilegesEvaluationException {
        return new FieldMaskingRule.MultiRole(rules);
    }

    public static abstract class FieldMaskingRule extends AbstractRuleBasedPrivileges.Rule {
        public static final FieldMaskingRule ALLOW_ALL = new FieldMaskingRule.SingleRole(ImmutableList.of());

        public static FieldMaskingRule of(FieldMasking.Config fieldMaskingConfig, String... rules)
            throws PrivilegesConfigurationValidationException {
            ImmutableList.Builder<Field> patterns = new ImmutableList.Builder<>();

            for (String rule : rules) {
                patterns.add(new Field(new FieldMaskingExpression(rule), fieldMaskingConfig));
            }

            return new SingleRole(patterns.build());
        }

        public abstract Field get(String field);

        public abstract boolean isAllowAll();

        public boolean isMasked(String field) {
            return get(field) != null;
        }

        public boolean isUnrestricted() {
            return this.isAllowAll();
        }

        public abstract List<String> getSource();

        public static class SingleRole extends FieldMaskingRule {

            final RoleV7.Index sourceIndex;
            final ImmutableList<FieldMaskingRule.Field> expressions;

            SingleRole(RoleV7.Index sourceIndex, FieldMasking.Config fieldMaskingConfig) throws PrivilegesConfigurationValidationException {
                this.sourceIndex = sourceIndex;
                this.expressions = parseExpressions(sourceIndex, fieldMaskingConfig);
            }

            SingleRole(ImmutableList<Field> expressions) {
                this.sourceIndex = null;
                this.expressions = expressions;
            }

            public Field get(String field) {
                return internalGet(stripKeywordSuffix(field));
            }

            private Field internalGet(String field) {
                for (Field expression : this.expressions) {
                    if (expression.getPattern().test(field)) {
                        return expression;
                    }
                }

                return null;
            }

            public boolean isAllowAll() {
                return expressions.isEmpty();
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FM:*";
                } else {
                    return "FM:" + expressions;
                }
            }

            @Override
            public List<String> getSource() {
                return this.expressions.stream().map(FieldMaskingRule.Field::getSource).collect(Collectors.toList());
            }

            static ImmutableList<FieldMaskingRule.Field> parseExpressions(RoleV7.Index index, FieldMasking.Config fieldMaskingConfig)
                throws PrivilegesConfigurationValidationException {
                if (index.getMasked_fields() == null || index.getMasked_fields().isEmpty()) {
                    return ImmutableList.of();
                }

                ImmutableList.Builder<FieldMaskingRule.Field> result = ImmutableList.builder();

                for (String source : index.getMasked_fields()) {
                    result.add(new Field(new FieldMaskingExpression(source), fieldMaskingConfig));
                }

                return result.build();
            }
        }

        public static class MultiRole extends FieldMaskingRule {
            final ImmutableList<FieldMaskingRule.SingleRole> parts;
            final boolean allowAll;

            MultiRole(Collection<FieldMaskingRule.SingleRole> parts) {
                this.parts = ImmutableList.copyOf(parts);
                this.allowAll = this.parts.stream().anyMatch((p) -> p.isAllowAll());
            }

            public Field get(String field) {
                field = stripKeywordSuffix(field);

                Field masking = null;

                for (FieldMaskingRule.SingleRole part : parts) {
                    masking = part.get(field);

                    if (masking == null) {
                        return null;
                    }
                }

                return masking;
            }

            public boolean isAllowAll() {
                return allowAll;
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FM:*";
                } else {
                    return "FM:" + parts.stream().map((p) -> p.expressions).collect(Collectors.toList());
                }
            }

            @Override
            public List<String> getSource() {
                return this.parts.stream().flatMap(r -> r.getSource().stream()).collect(Collectors.toList());
            }
        }

        public static class Field {
            private final FieldMaskingExpression expression;

            private final String hashAlgorithm;
            private final Salt salt;
            private final byte[] saltBytes;

            Field(FieldMaskingExpression expression, FieldMasking.Config fieldMaskingConfig) {
                this.expression = expression;
                this.hashAlgorithm = expression.getAlgoName() != null ? expression.getAlgoName()
                    : StringUtils.isNotEmpty(fieldMaskingConfig.getDefaultHashAlgorithm()) ? fieldMaskingConfig.getDefaultHashAlgorithm()
                    : null;
                this.salt = fieldMaskingConfig.getSalt();
                this.saltBytes = this.salt.getSalt16();
            }

            public WildcardMatcher getPattern() {
                return expression.getPattern();
            }

            public byte[] apply(byte[] value) {
                if (this.hashAlgorithm != null) {
                    return customHash(value, this.hashAlgorithm);
                } else if (expression.getRegexReplacements() != null) {
                    return applyRegexReplacements(value, expression.getRegexReplacements());
                } else {
                    return blake2bHash(value);
                }
            }

            public String apply(String value) {
                return new String(apply(value.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
            }

            public BytesRef apply(BytesRef value) {
                if (value == null) {
                    return null;
                }

                return new BytesRef(apply(BytesRef.deepCopyOf(value).bytes));
            }

            @Override
            public String toString() {
                return expression.toString();
            }

            public String getSource() {
                return expression.getSource();
            }

            private static byte[] customHash(byte[] in, String algorithm) {
                try {
                    MessageDigest digest = MessageDigest.getInstance(algorithm);
                    return Hex.encode(digest.digest(in));
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalArgumentException(e);
                }
            }

            private byte[] applyRegexReplacements(byte[] value, List<FieldMaskingExpression.RegexReplacement> regexReplacements) {
                String string = new String(value, StandardCharsets.UTF_8);
                for (FieldMaskingExpression.RegexReplacement rr : regexReplacements) {
                    string = rr.getRegex().matcher(string).replaceAll(rr.getReplacement());
                }
                return string.getBytes(StandardCharsets.UTF_8);
            }

            private byte[] blake2bHash(byte[] in) {
                // Salt is passed incorrectly but order of parameters is retained at present to ensure full backwards compatibility
                // Tracking with https://github.com/opensearch-project/security/issues/4274
                final Blake2b hash = new Blake2b(null, 32, null, saltBytes);
                hash.update(in, 0, in.length);
                final byte[] out = new byte[hash.getDigestSize()];
                hash.digest(out, 0);

                return Hex.encode(out);
            }
        }

        static String stripKeywordSuffix(String field) {
            if (field.endsWith(".keyword")) {
                return field.substring(0, field.length() - ".keyword".length());
            } else {
                return field;
            }
        }
    }

    public static class FieldMaskingExpression {
        public static final FieldMaskingExpression MASK_ALL = new FieldMaskingExpression(WildcardMatcher.ANY, "*");

        private final WildcardMatcher pattern;
        private final MessageDigest algo;
        private final String algoName;
        private final List<RegexReplacement> regexReplacements;
        private final String source;

        public FieldMaskingExpression(String value) throws PrivilegesConfigurationValidationException {
            this.source = value;

            // TODO check
            List<String> tokens = Splitter.on("::").splitToList(value);
            pattern = WildcardMatcher.from(tokens.get(0));

            if (tokens.size() == 1) {
                algo = null;
                algoName = null;
                regexReplacements = null;
            } else if (tokens.size() == 2) {
                regexReplacements = null;
                try {
                    this.algoName = tokens.get(1);
                    this.algo = MessageDigest.getInstance(tokens.get(1));
                } catch (NoSuchAlgorithmException e) {
                    throw new PrivilegesConfigurationValidationException("Invalid algorithm " + tokens.get(1));
                }
            } else if (tokens.size() % 2 == 1) {
                algo = null;
                algoName = null;
                regexReplacements = new ArrayList<>((tokens.size() - 1) / 2);
                for (int i = 1; i < tokens.size() - 1; i = i + 2) {
                    regexReplacements.add(new RegexReplacement(tokens.get(i), tokens.get(i + 1)));
                }
            } else {
                throw new PrivilegesConfigurationValidationException(
                    "A field masking expression must have the form 'field_name', 'field_name::algorithm', 'field_name::regex::replacement' or 'field_name::(regex::replacement)+'"
                );
            }
        }

        private FieldMaskingExpression(WildcardMatcher pattern, String source) {
            this.pattern = pattern;
            this.source = source;
            this.algo = null;
            this.algoName = null;
            this.regexReplacements = null;
        }

        public static class RegexReplacement {
            private final java.util.regex.Pattern regex;
            private final String replacement;

            public RegexReplacement(String regex, String replacement) throws PrivilegesConfigurationValidationException {
                if (!regex.startsWith("/") || !regex.endsWith("/")) {
                    throw new PrivilegesConfigurationValidationException("A regular expression needs to be wrapped in /.../");
                }

                try {
                    this.regex = java.util.regex.Pattern.compile(regex.substring(1).substring(0, regex.length() - 2));
                } catch (PatternSyntaxException e) {
                    throw new PrivilegesConfigurationValidationException(e.getMessage(), e);
                }

                this.replacement = replacement;
            }

            public java.util.regex.Pattern getRegex() {
                return regex;
            }

            public String getReplacement() {
                return replacement;
            }

            @Override
            public String toString() {
                return "RegexReplacement [regex=" + regex + ", replacement=" + replacement + "]";
            }

        }

        @Override
        public String toString() {
            return source;
        }

        public MessageDigest getAlgo() {
            return algo;
        }

        public String getAlgoName() {
            return algoName;
        }

        public List<RegexReplacement> getRegexReplacements() {
            return regexReplacements;
        }

        public WildcardMatcher getPattern() {
            return pattern;
        }

        public String getSource() {
            return source;
        }
    }

    public static class Config {
        public static Config fromSettings(Settings settings) {
            return new Config(settings.get(ConfigConstants.SECURITY_MASKED_FIELDS_ALGORITHM_DEFAULT), Salt.from(settings));
        }

        private final String defaultHashAlgorithm;
        private final Salt salt;

        Config(String defaultHashAlgorithm, Salt salt) {
            this.defaultHashAlgorithm = defaultHashAlgorithm;
            this.salt = salt;
        }

        public String getDefaultHashAlgorithm() {
            return defaultHashAlgorithm;
        }

        public Salt getSalt() {
            return salt;
        }
    }

}
