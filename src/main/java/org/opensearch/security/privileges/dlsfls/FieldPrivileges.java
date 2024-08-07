package org.opensearch.security.privileges.dlsfls;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
            ImmutableList.Builder<FlsPattern> patterns = new ImmutableList.Builder<>();

            for (String rule : rules) {
                patterns.add(new FlsPattern(rule));
            }

            return new SingleRole(patterns.build());
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

        public static final FlsRule ALLOW_ALL = new FlsRule.SingleRole(ImmutableList.of());
        public static final FlsRule DENY_ALL = new FlsRule.SingleRole(ImmutableList.of(FlsPattern.EXCLUDE_ALL));

        public abstract boolean isAllowed(String field);

        public abstract boolean isAllowAll();

        public boolean isUnrestricted() {
            return this.isAllowAll();
        }

        public abstract List<String> getSource();

        static class SingleRole extends FlsRule {
            final RoleV7.Index sourceIndex;
            final ImmutableList<FlsPattern> patterns;
            final Map<String, Boolean> cache;
            final boolean allowAll;

            SingleRole(RoleV7.Index sourceIndex) throws PrivilegesConfigurationValidationException {
                this.sourceIndex = sourceIndex;

                int exclusions = 0;
                int inclusions = 0;

                ImmutableList.Builder<FlsPattern> flsPatterns = ImmutableList.builder();

                for (String flsPatternSource : sourceIndex.getFls()) {
                    try {
                        FlsPattern flsPattern = new FlsPattern(flsPatternSource);
                        flsPatterns.add(flsPattern);

                        if (flsPattern.isExcluded()) {
                            exclusions++;
                        } else {
                            inclusions++;
                        }
                    } catch (PrivilegesConfigurationValidationException e) {
                        throw new PrivilegesConfigurationValidationException("Invalid FLS pattern in " + sourceIndex, e);
                    }
                }

                if (exclusions == 0 && inclusions == 0) {
                    // Empty
                    this.patterns = ImmutableList.of(FlsPattern.INCLUDE_ALL);
                } else if (exclusions != 0 && inclusions == 0) {
                    // Only exclusions TODO check
                    this.patterns = flsPatterns.build();
                } else if (exclusions == 0 && inclusions != 0) {
                    // Only inclusions
                    // We prepend to the list of inclusions one "exclude all" rule.
                    // The evaluation algorithm in internalIsAllowed() (see below) will then start with a
                    // "include nothing" state and gradually include the patterns.
                    this.patterns = ImmutableList.<FlsPattern>builder().add(FlsPattern.EXCLUDE_ALL).addAll(flsPatterns.build()).build();
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
                    this.patterns = flsPatterns.build().stream().filter(e -> e.isExcluded()).collect(ImmutableList.toImmutableList());
                }

                this.allowAll = patterns.isEmpty()
                    || (patterns.size() == 1 && patterns.get(0).getPattern() == WildcardMatcher.ANY && !patterns.get(0).isExcluded());

                if (this.allowAll) {
                    this.cache = null;
                } else {
                    this.cache = new ConcurrentHashMap<String, Boolean>();
                }
            }

            public SingleRole(ImmutableList<FlsPattern> patterns) {
                this.patterns = patterns;
                this.sourceIndex = null;
                this.allowAll = patterns.isEmpty()
                    || (patterns.size() == 1 && patterns.get(0).getPattern() == WildcardMatcher.ANY && !patterns.get(0).isExcluded());
                this.cache = null;
            }

            public boolean isAllowed(String field) {
                if (cache == null) {
                    return internalIsAllowed(field);
                } else {
                    Boolean allowed = this.cache.get(field);

                    if (allowed != null) {
                        return allowed;
                    } else {
                        allowed = internalIsAllowed(field);
                        this.cache.put(field, allowed);
                        return allowed;
                    }
                }
            }

            private boolean internalIsAllowed(String field) {
                field = stripKeywordSuffix(field);

                boolean allowed = true;

                for (FlsPattern pattern : this.patterns) {
                    if (pattern.getPattern().test(field)) {
                        if (pattern.isExcluded()) {
                            allowed = false;
                        } else {
                            allowed = true;
                        }
                    }
                }

                return allowed;
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
            final Map<String, Boolean> cache;
            final boolean allowAll;

            MultiRole(ImmutableList<SingleRole> entries) {
                this.entries = entries;
                this.allowAll = entries.stream().anyMatch((e) -> e.isAllowAll());

                if (this.allowAll) {
                    this.cache = null;
                } else {
                    this.cache = new ConcurrentHashMap<String, Boolean>();
                }
            }

            public boolean isAllowed(String field) {
                if (allowAll) {
                    return true;
                } else if (cache == null) {
                    return internalIsAllowed(field);
                } else {
                    Boolean allowed = this.cache.get(field);

                    if (allowed != null) {
                        return allowed;
                    } else {
                        allowed = internalIsAllowed(field);
                        this.cache.put(field, allowed);
                        return allowed;
                    }
                }
            }

            private boolean internalIsAllowed(String field) {
                field = stripKeywordSuffix(field);

                // TODO check
                for (SingleRole entry : this.entries) {
                    if (entry.isAllowed(field)) {
                        return true;
                    }
                }

                return false;
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
            if (string.startsWith("~") || string.startsWith("!")) {
                excluded = true;
                pattern = WildcardMatcher.from(string.substring(1));
            } else {
                pattern = WildcardMatcher.from(string);
                excluded = false;
            }

            this.source = string;
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
    }

}
