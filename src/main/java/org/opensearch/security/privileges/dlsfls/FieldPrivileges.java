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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.WildcardMatcher;

public class FieldPrivileges extends AbstractRuleBasedPrivileges<FieldPrivileges.FlsRule, FieldPrivileges.FlsRule> {
    public FieldPrivileges(SecurityDynamicConfiguration<RoleV7> roles, Map<String, IndexAbstraction> indexMetadata, Settings settings) {
        super(roles, indexMetadata, FieldPrivileges::roleToRule, settings);
    }

    static FlsRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
        List<String> flsPatterns = rolePermissions.getFls();

        if (flsPatterns != null && !flsPatterns.isEmpty()) {
            return new FlsRule.SingleRole(rolePermissions);
        } else {
            return null;
        }
    }

    @Override
    protected FlsRule unrestricted() {
        return FlsRule.ALLOW_ALL;
    }

    @Override
    protected FlsRule fullyRestricted() {
        return FlsRule.DENY_ALL;
    }

    @Override
    protected FlsRule compile(PrivilegesEvaluationContext context, Collection<FlsRule> rules) throws PrivilegesEvaluationException {
        if (rules.isEmpty()) {
            return FlsRule.DENY_ALL;
        } else {
            return FlsRule.merge(rules);
        }
    }

    public static abstract class FlsRule extends AbstractRuleBasedPrivileges.Rule {
        public static FlsRule of(String... rules) throws PrivilegesConfigurationValidationException {
            return new SingleRole(FlsPattern.parse(Arrays.asList(rules)), null);
        }

        static FlsRule merge(Collection<FlsRule> rules) {
            if (rules.size() == 1) {
                return rules.iterator().next();
            }

            ImmutableList.Builder<SingleRole> entries = ImmutableList.builderWithExpectedSize(rules.size());

            for (FlsRule rule : rules) {
                if (rule instanceof SingleRole) {
                    entries.add((SingleRole) rule);
                } else if (rule instanceof MultiRole) {
                    for (SingleRole subRule : ((MultiRole) rule).entries) {
                        entries.add(subRule);
                    }
                }
            }

            return new FlsRule.MultiRole(entries.build());
        }

        public static final FlsRule ALLOW_ALL = new FlsRule.SingleRole(ImmutableList.of(), null);
        public static final FlsRule DENY_ALL = new FlsRule.SingleRole(ImmutableList.of(FlsPattern.EXCLUDE_ALL), null);

        public abstract boolean isAllowed(String field);

        public abstract boolean isAllowAll();

        public boolean isUnrestricted() {
            return this.isAllowAll();
        }

        public abstract List<String> getSource();

        static class SingleRole extends FlsRule {
            final RoleV7.Index sourceIndex;
            final ImmutableList<FlsPattern> patterns;
            final ImmutableList<FlsPattern> effectivePatterns;
            final boolean allowAll;
            final boolean excluding;

            SingleRole(RoleV7.Index sourceIndex) throws PrivilegesConfigurationValidationException {
                this(FlsPattern.parse(sourceIndex.getFls()), sourceIndex);
            }

            public SingleRole(List<FlsPattern> patterns, RoleV7.Index sourceIndex) {
                this.sourceIndex = sourceIndex;

                List<FlsPattern> flsPatternsExcluding = new ArrayList<>(patterns.size());
                List<FlsPattern> flsPatternsIncluding = new ArrayList<>(patterns.size());

                for (FlsPattern flsPattern : patterns) {

                    if (flsPattern.isExcluded()) {
                        flsPatternsExcluding.add(flsPattern);
                    } else {
                        flsPatternsIncluding.add(flsPattern);
                    }

                }

                int exclusions = flsPatternsExcluding.size();
                int inclusions = flsPatternsIncluding.size();

                if (exclusions == 0 && inclusions == 0) {
                    // Empty
                    this.effectivePatterns = this.patterns = ImmutableList.of(FlsPattern.INCLUDE_ALL);
                    this.excluding = false;
                } else if (exclusions != 0 && inclusions == 0) {
                    // Only exclusions
                    this.effectivePatterns = this.patterns = ImmutableList.copyOf(flsPatternsExcluding);
                    this.excluding = true;
                } else if (exclusions == 0 && inclusions != 0) {
                    // Only inclusions
                    this.effectivePatterns = this.patterns = ImmutableList.copyOf(flsPatternsIncluding);
                    this.excluding = false;
                } else {
                    // Mixed inclusions and exclusions
                    //
                    // While the docs say that mixing inclusions and exclusions is not supported, the original
                    // implementation only regarded exclusions and disregarded inclusions if these were mixed.
                    // We are mirroring this behaviour here. It might make sense to rethink the semantics here,
                    // though, as there might be semantics which make more sense.
                    //
                    // See:
                    // https://github.com/opensearch-project/security/blob/e73fc24509363cb1573607c6cf47c98780fc89de/src/main/java/org/opensearch/security/configuration/DlsFlsFilterLeafReader.java#L658-L662
                    // https://opensearch.org/docs/latest/security/access-control/field-level-security/
                    this.patterns = ImmutableList.copyOf(patterns);
                    this.effectivePatterns = ImmutableList.copyOf(flsPatternsExcluding);
                    this.excluding = true;
                }

                this.allowAll = patterns.isEmpty()
                    || (patterns.size() == 1 && patterns.get(0).getPattern() == WildcardMatcher.ANY && !patterns.get(0).isExcluded());
            }

            public boolean isAllowed(String field) {
                if (isAllowAll()) {
                    return true;
                }

                field = stripKeywordSuffix(field);

                if (excluding) {
                    for (FlsPattern pattern : this.effectivePatterns) {
                        assert pattern.isExcluded();
                        if (pattern.getPattern().test(field)) {
                            return false;
                        }
                    }
                    return true;
                } else {
                    // including
                    for (FlsPattern pattern : this.effectivePatterns) {
                        assert !pattern.isExcluded();
                        if (pattern.getPattern().test(field)) {
                            return true;
                        }
                    }
                    return false;
                }
            }

            public boolean isAllowAll() {
                return allowAll;
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FLS:*";
                } else {
                    return "FLS:" + patterns;
                }
            }

            @Override
            public List<String> getSource() {
                return patterns.stream().map(FlsPattern::getSource).collect(ImmutableList.toImmutableList());
            }
        }

        static class MultiRole extends FlsRule {
            final ImmutableList<SingleRole> entries;
            final ImmutableList<SingleRole> effectiveEntries;

            final boolean allowAll;
            final boolean excluding;

            MultiRole(ImmutableList<SingleRole> entries) {
                this.entries = entries;
                this.allowAll = entries.stream().anyMatch((e) -> e.isAllowAll());

                if (this.allowAll) {
                    this.effectiveEntries = entries;
                    this.excluding = false;
                } else {
                    long excluding = entries.stream().filter(e -> e.excluding).count();
                    long including = entries.size() - excluding;

                    if (excluding != 0 && including == 0) {
                        this.effectiveEntries = entries;
                        this.excluding = true;
                    } else if (excluding == 0 && including != 0) {
                        this.effectiveEntries = entries;
                        this.excluding = false;
                    } else {
                        // Only use excluding entries
                        this.effectiveEntries = entries.stream().filter(e -> e.excluding).collect(ImmutableList.toImmutableList());
                        this.excluding = true;
                    }
                }
            }

            public boolean isAllowed(String field) {
                if (allowAll) {
                    return true;
                } else {
                    if (excluding) {
                        for (SingleRole rule : entries) {
                            if (!rule.isAllowed(field)) {
                                return false;
                            }
                        }
                        return true;
                    } else {
                        // including
                        for (SingleRole rule : entries) {
                            if (rule.isAllowed(field)) {
                                return true;
                            }
                        }
                        return false;
                    }
                }
            }

            public boolean isAllowAll() {
                return allowAll;
            }

            @Override
            public String toString() {
                if (isAllowAll()) {
                    return "FLS:*";
                } else {
                    return "FLS:" + entries.stream().map((e) -> e.patterns).collect(Collectors.toList());
                }
            }

            @Override
            public List<String> getSource() {
                return entries.stream().flatMap(e -> e.getSource().stream()).collect(ImmutableList.toImmutableList());
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

    public static class FlsPattern {
        public static final FlsPattern INCLUDE_ALL = new FlsPattern(WildcardMatcher.ANY, false, "*");
        public static final FlsPattern EXCLUDE_ALL = new FlsPattern(WildcardMatcher.ANY, true, "~*");

        private final boolean excluded;
        private final WildcardMatcher pattern;
        private final String source;

        public FlsPattern(String string) throws PrivilegesConfigurationValidationException {
            try {
                if (string.startsWith("~") || string.startsWith("!")) {
                    excluded = true;
                    pattern = WildcardMatcher.from(string.substring(1));
                } else {
                    pattern = WildcardMatcher.from(string);
                    excluded = false;
                }

                this.source = string;
            } catch (PatternSyntaxException e) {
                throw new PrivilegesConfigurationValidationException(e.getMessage(), e);
            }
        }

        FlsPattern(WildcardMatcher pattern, boolean excluded, String source) {
            this.pattern = pattern;
            this.excluded = excluded;
            this.source = source;
        }

        public String getSource() {
            return source;
        }

        public WildcardMatcher getPattern() {
            return pattern;
        }

        public boolean isExcluded() {
            return excluded;
        }

        @Override
        public String toString() {
            return source;
        }

        public static List<FlsPattern> parse(List<String> flsPatternStrings) throws PrivilegesConfigurationValidationException {
            List<FlsPattern> flsPatterns = new ArrayList<>(flsPatternStrings.size());

            for (String flsPatternSource : flsPatternStrings) {
                try {
                    flsPatterns.add(new FlsPattern(flsPatternSource));
                } catch (PrivilegesConfigurationValidationException e) {
                    throw new PrivilegesConfigurationValidationException("Invalid FLS pattern " + flsPatternSource, e);
                }
            }

            return flsPatterns;
        }
    }

}
