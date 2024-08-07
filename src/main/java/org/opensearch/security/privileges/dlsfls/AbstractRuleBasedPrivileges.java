package org.opensearch.security.privileges.dlsfls;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.ImmutableMap;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.privileges.IndexPattern;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import com.selectivem.collections.CompactMapGroupBuilder;
import com.selectivem.collections.DeduplicatingCompactSubSetBuilder;

/**
 * Abstract super class which provides common DLS/FLS/FM rule evaluation functionality for the concrete classes
 * DocumentPrivileges, FieldPrivileges and FieldMasking.
 *
 * @param <SingleRule> A single DLS/FLS/FM rule as defined in roles.yml.
 * @param <JoinedRule> A merged DLS/FLS/FM rule that might contain SingleRules from several roles that apply to a user at the same time.
 */
abstract class AbstractRuleBasedPrivileges<SingleRule, JoinedRule extends AbstractRuleBasedPrivileges.Rule> {
    private static final Logger log = LogManager.getLogger(AbstractRuleBasedPrivileges.class);

    protected final SecurityDynamicConfiguration<RoleV7> roles;
    protected final StaticRules.Index<SingleRule> staticIndexRules;
    private final RoleToRuleFunction<SingleRule> roleToRuleFunction;
    private final boolean dfmEmptyOverwritesAll;

    private volatile StatefulRules<SingleRule> statefulRules;

    public AbstractRuleBasedPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        RoleToRuleFunction<SingleRule> roleToRuleFunction,
        Settings settings
    ) {
        this.roles = roles;
        this.roleToRuleFunction = roleToRuleFunction;
        this.staticIndexRules = new StaticRules.Index<>(roles, roleToRuleFunction);
        this.dfmEmptyOverwritesAll = settings.getAsBoolean(ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL, false);

        if (indexMetadata != null) {
            this.statefulRules = new StatefulRules<>(roles, indexMetadata, roleToRuleFunction);
        }
    }

    /**
     * Returns true if the user identified in the PrivilegesEvaluationContext does not have any restrictions in any case,
     * independently of the indices they are requesting.
     */
    public boolean isUniversallyUnrestricted(PrivilegesEvaluationContext context) {
        if (this.dfmEmptyOverwritesAll
            && CollectionUtils.containsAny(this.staticIndexRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if the user identified in the PrivilegesEvaluationContext does not have any restrictions for the
     * given resolved indices.
     *
     * @throws PrivilegesEvaluationException If something went wrong during privileges evaluation. In such cases, any
     * access should be denied to make sure that no unauthorized information is exposed.
     */
    public boolean isUnrestricted(PrivilegesEvaluationContext context, IndexResolverReplacer.Resolved resolved)
        throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return false;
        }

        if (this.dfmEmptyOverwritesAll
            && CollectionUtils.containsAny(this.staticIndexRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        if (resolved == null) {
            return false;
        }

        if (CollectionUtils.containsAny(this.staticIndexRules.roleWithIndexWildcardToRule.keySet(), context.getMappedRoles())) {
            return false;
        }

        StatefulRules<SingleRule> statefulRules = this.statefulRules;

        // The logic is here a bit tricky: For each index/alias/data stream we assume restrictions until we found an unrestricted role.
        // If we found an unrestricted role, we continue with the next index/alias/data stream. If we found a restricted role, we abort
        // early and return true.

        for (String index : resolved.getAllIndicesResolved(context.getClusterStateSupplier(), context.getIndexNameExpressionResolver())) {
            IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);

            if (indexAbstraction == null) {
                // We have got a request for an index that does not exist.
                // For non-existing indices, it is safe to assume that no documents can be accessed.

                if (log.isDebugEnabled()) {
                    log.debug("ResolvedIndices {} contain non-existing indices. Assuming full document restriction.", resolved);
                }

                return false;
            }

            if (!isUnrestrictedExplicit(context, statefulRules, indexAbstraction)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns true if there are roles without a rule which imposes restrictions for the particular index.
     * Does consider rules with index wildcards ("*").
     */
    public boolean isUnrestricted(PrivilegesEvaluationContext context, StatefulRules<SingleRule> statefulRules, String index)
        throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return false;
        }

        if (CollectionUtils.containsAny(this.staticIndexRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return true;
        }

        IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);
        if (indexAbstraction == null) {
            // We have got a request for an index that does not exist.
            // For non-existing indices, it is safe to assume that no documents can be accessed.
            return false;
        }

        return isUnrestrictedExplicit(context, statefulRules, indexAbstraction);
    }

    /**
     * Returns true if there are roles without a rule which imposes restrictions for the particular index.
     * Does not consider rules with index wildcards ("*").
     */
    private boolean isUnrestrictedExplicit(
        PrivilegesEvaluationContext context,
        StatefulRules<SingleRule> statefulRules,
        IndexAbstraction indexAbstraction
    ) throws PrivilegesEvaluationException {

        String index = indexAbstraction.getName();

        if (this.dfmEmptyOverwritesAll) {
            // We assume that we have a restriction unless there are roles without restriction.
            // Thus, we only have to check the roles without restriction.

            if (statefulRules != null && statefulRules.covers(index)) {
                Set<String> roleWithoutRule = statefulRules.indexToRoleWithoutRule.get(index);

                if (roleWithoutRule != null && CollectionUtils.containsAny(roleWithoutRule, context.getMappedRoles())) {
                    return true;
                }
            } else {
                if (this.staticIndexRules.hasUnrestrictedPatterns(context, index)) {
                    return true;
                }
            }

            if (this.staticIndexRules.hasUnrestrictedPatternTemplates(context, index)) {
                return true;
            }

            for (IndexAbstraction parent : getParents(indexAbstraction, context.getIndicesLookup())) {
                if (isUnrestrictedExplicit(context, statefulRules, parent)) {
                    return true;
                }
            }

            // If we found no roles without restriction, we assume a restriction
            return false;
        } else {
            // if dfmEmptyOverwritesAll == false, we assume an unrestricted index until a restriction is found

            if (statefulRules != null && statefulRules.covers(index)) {
                Map<String, SingleRule> roleWithRule = statefulRules.indexToRoleToRule.get(index);

                if (roleWithRule != null && CollectionUtils.containsAny(roleWithRule.keySet(), context.getMappedRoles())) {
                    return false;
                }
            } else {
                if (this.staticIndexRules.hasRestrictedPatterns(context, index)) {
                    return false;
                }
            }

            if (this.staticIndexRules.hasRestrictedPatternTemplates(context, index)) {
                return false;
            }

            for (IndexAbstraction parent : getParents(indexAbstraction, context.getIndicesLookup())) {
                if (!isUnrestrictedExplicit(context, statefulRules, parent)) {
                    return false;
                }
            }

            return true;
        }
    }

    public JoinedRule getRestriction(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
        return getRestrictionImpl(context, index);
    }

    protected JoinedRule getRestrictionImpl(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
        if (context.getMappedRoles().isEmpty()) {
            return fullyRestricted();
        }

        if (this.dfmEmptyOverwritesAll
            && CollectionUtils.containsAny(this.staticIndexRules.rolesWithIndexWildcardWithoutRule, context.getMappedRoles())) {
            return unrestricted();
        }

        IndexAbstraction indexAbstraction = context.getIndicesLookup().get(index);
        if (indexAbstraction == null) {
            // We have got a request for an index that does not exist.
            // For non-existing indices, it is safe to assume that no documents can be accessed.
            return fullyRestricted();
        }

        StatefulRules<SingleRule> statefulRules = this.statefulRules;
        if (statefulRules != null && !statefulRules.covers(index)) {
            statefulRules = null;
        }

        if (this.dfmEmptyOverwritesAll && isUnrestrictedExplicit(context, statefulRules, indexAbstraction)) {
            return unrestricted();
        }

        // We have determined that there are no matching roles that give us unrestricted access.
        // Thus, let's collect the rules.

        Set<SingleRule> ruleSink = new HashSet<>();

        collectRules(context, ruleSink, indexAbstraction);

        for (IndexAbstraction parent : getParents(indexAbstraction, context.getIndicesLookup())) {
            collectRules(context, ruleSink, parent);
        }

        if (ruleSink.isEmpty()) {
            if (this.dfmEmptyOverwritesAll) {
                return fullyRestricted();
            } else {
                return unrestricted();
            }
        } else {
            return compile(context, ruleSink);
        }
    }

    public IndexToRuleMap<JoinedRule> getRestrictions(PrivilegesEvaluationContext context, Collection<String> indices)
        throws PrivilegesEvaluationException {
        if (isUniversallyUnrestricted(context)) {
            return IndexToRuleMap.unrestricted();
        }

        ImmutableMap.Builder<String, JoinedRule> result = ImmutableMap.builderWithExpectedSize(indices.size());

        int restrictedIndices = 0;

        for (String index : indices) {
            JoinedRule restriction = getRestrictionImpl(context, index);

            if (!restriction.isUnrestricted()) {
                restrictedIndices++;
            }

            result.put(index, restriction);
        }

        if (restrictedIndices == 0) {
            return IndexToRuleMap.unrestricted();
        }

        return new IndexToRuleMap<>(result.build());
    }

    private void collectRules(PrivilegesEvaluationContext context, Set<SingleRule> ruleSink, IndexAbstraction indexAbstraction)
        throws PrivilegesEvaluationException {
        String index = indexAbstraction.getName();
        Map<String, SingleRule> statefulRoleToRule = null;
        boolean statefulRulesEffective;

        if (statefulRules != null && statefulRules.covers(index)) {
            statefulRoleToRule = statefulRules.indexToRoleToRule.get(index);
            statefulRulesEffective = true;
        } else {
            statefulRulesEffective = false;
        }

        for (String role : context.getMappedRoles()) {
            {
                SingleRule rule = this.staticIndexRules.roleWithIndexWildcardToRule.get(role);

                if (rule != null) {
                    ruleSink.add(rule);
                }
            }

            if (statefulRoleToRule != null) {
                SingleRule rule = statefulRoleToRule.get(role);

                if (rule != null) {
                    ruleSink.add(rule);
                }
            }

            if (!statefulRulesEffective) {
                // Only when we have no stateful information, we also check the static index patterns

                Map<WildcardMatcher, SingleRule> indexPatternToRule = this.staticIndexRules.rolesToStaticIndexPatternToRule.get(role);
                if (indexPatternToRule != null) {
                    for (Map.Entry<WildcardMatcher, SingleRule> entry : indexPatternToRule.entrySet()) {
                        WildcardMatcher pattern = entry.getKey();

                        if (pattern.test(index)) {
                            ruleSink.add(entry.getValue());
                        }
                    }
                }
            }

            Map<IndexPattern, SingleRule> dynamicIndexPatternToRule = this.staticIndexRules.rolesToDynamicIndexPatternToRule.get(role);

            if (dynamicIndexPatternToRule != null) {
                for (Map.Entry<IndexPattern, SingleRule> entry : dynamicIndexPatternToRule.entrySet()) {
                    try {
                        if (entry.getKey().matches(index, context, context.getIndicesLookup())) {
                            ruleSink.add(entry.getValue());
                        }
                    } catch (PrivilegesEvaluationException e) {
                        throw new PrivilegesEvaluationException("Error while evaluating index pattern of role " + role, e);
                    }
                }
            }
        }
    }

    protected abstract JoinedRule unrestricted();

    protected abstract JoinedRule fullyRestricted();

    protected abstract JoinedRule compile(PrivilegesEvaluationContext context, Collection<SingleRule> rules)
        throws PrivilegesEvaluationException;

    public synchronized void updateIndices(Map<String, IndexAbstraction> indexMetadata) {
        StatefulRules<SingleRule> statefulRules = this.statefulRules;

        if (statefulRules == null || !statefulRules.indexMetadata.keySet().equals(indexMetadata.keySet())) {
            this.statefulRules = new StatefulRules<>(roles, indexMetadata, this.roleToRuleFunction);
        }
    }

    /**
     * Returns aliases and/or data streams containing the specified index.
     */
    private Collection<IndexAbstraction> getParents(IndexAbstraction indexAbstraction, Map<String, IndexAbstraction> indexMetadata) {
        if (indexAbstraction instanceof IndexAbstraction.Index) {
            IndexAbstraction.Index index = (IndexAbstraction.Index) indexAbstraction;

            if (index.getWriteIndex().getAliases().isEmpty() && index.getParentDataStream() == null) {
                return Collections.emptySet();
            }

            List<IndexAbstraction> result = new ArrayList<>(index.getWriteIndex().getAliases().size() + 1);

            for (String aliasName : index.getWriteIndex().getAliases().keySet()) {
                IndexAbstraction alias = indexMetadata.get(aliasName);

                if (alias == null) {
                    throw new RuntimeException("Inconsistent index lookup; cannot find " + aliasName);
                }

                result.add(alias);
            }

            if (indexAbstraction.getParentDataStream() != null) {
                result.add(indexAbstraction.getParentDataStream());
            }

            return result;
        } else {
            return Collections.emptySet();
        }
    }

    private Set<String> getParentAliases(IndexAbstraction indexAbstraction) {
        if (indexAbstraction instanceof IndexAbstraction.Index) {
            return ((IndexAbstraction.Index) indexAbstraction).getWriteIndex().getAliases().keySet();
        } else {
            return Collections.emptySet();
        }
    }

    static class StaticRules<SingleRule> {

        static class Index<SingleRule> extends StaticRules<SingleRule> {
            Index(SecurityDynamicConfiguration<RoleV7> roles, RoleToRuleFunction<SingleRule> roleToRuleFunction) {
                super(roles, "index", roleToRuleFunction);
            }
        }

        protected final Set<String> rolesWithIndexWildcardWithoutRule;
        protected final Map<String, SingleRule> roleWithIndexWildcardToRule;
        protected final Map<String, Map<IndexPattern, SingleRule>> rolesToDynamicIndexPatternToRule;
        protected final Map<String, Set<IndexPattern>> rolesToDynamicIndexPatternWithoutRule;

        /**
         * Only used when no index metadata is available upon construction
         */
        protected final Map<String, Map<WildcardMatcher, SingleRule>> rolesToStaticIndexPatternToRule;

        /**
         * Only used when no index metadata is available upon construction
         */
        protected final Map<String, WildcardMatcher> rolesToStaticIndexPatternWithoutRule;

        protected final RoleToRuleFunction<SingleRule> roleToRuleFunction;

        StaticRules(SecurityDynamicConfiguration<RoleV7> roles, String objectName, RoleToRuleFunction<SingleRule> roleToRuleFunction) {
            this.roleToRuleFunction = roleToRuleFunction;

            Set<String> rolesWithIndexWildcardWithoutRule = new HashSet<>();
            Map<String, SingleRule> roleWithIndexWildcardToRule = new HashMap<>();
            Map<String, Map<IndexPattern, SingleRule>> rolesToDynamicIndexPatternToRule = new HashMap<>();
            Map<String, Set<IndexPattern>> rolesToDynamicIndexPatternWithoutRule = new HashMap<>();
            Map<String, Map<WildcardMatcher, SingleRule>> rolesToStaticIndexPatternToRule = new HashMap<>();
            Map<String, List<WildcardMatcher>> rolesToStaticIndexPatternWithoutRule = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    for (RoleV7.Index rolePermissions : role.getIndex_permissions()) {
                        if (rolePermissions.getIndex_patterns().contains("*")) {
                            SingleRule singleRule = this.roleToRule(rolePermissions);

                            if (singleRule == null) {
                                rolesWithIndexWildcardWithoutRule.add(roleName);
                            } else {
                                roleWithIndexWildcardToRule.put(roleName, singleRule);
                            }
                        } else {
                            SingleRule singleRule = this.roleToRule(rolePermissions);
                            IndexPattern indexPattern = IndexPattern.from(rolePermissions.getIndex_patterns());

                            if (indexPattern.hasStaticPattern()) {
                                if (singleRule == null) {
                                    rolesToStaticIndexPatternWithoutRule.computeIfAbsent(roleName, k -> new ArrayList<>())
                                        .add(indexPattern.getStaticPattern());
                                } else {
                                    rolesToStaticIndexPatternToRule.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .put(indexPattern.getStaticPattern(), singleRule);
                                }
                            }

                            if (indexPattern.hasDynamicPattern()) {
                                if (singleRule == null) {
                                    rolesToDynamicIndexPatternWithoutRule.computeIfAbsent(roleName, k -> new HashSet<>())
                                        .add(indexPattern.dynamicOnly());
                                } else {
                                    rolesToDynamicIndexPatternToRule.computeIfAbsent(roleName, k -> new HashMap<>())
                                        .put(indexPattern.dynamicOnly(), singleRule);
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry, e);
                }
            }

            this.rolesWithIndexWildcardWithoutRule = rolesWithIndexWildcardWithoutRule;
            this.roleWithIndexWildcardToRule = roleWithIndexWildcardToRule;
            this.rolesToDynamicIndexPatternToRule = rolesToDynamicIndexPatternToRule;
            this.rolesToDynamicIndexPatternWithoutRule = rolesToDynamicIndexPatternWithoutRule;

            this.rolesToStaticIndexPatternToRule = rolesToStaticIndexPatternToRule;
            this.rolesToStaticIndexPatternWithoutRule = rolesToStaticIndexPatternWithoutRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> WildcardMatcher.from(entry.getValue())));
        }

        protected SingleRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
            return this.roleToRuleFunction.apply(rolePermissions);
        }

        /**
         * Only to be used if there is no stateful index information
         */
        boolean hasUnrestrictedPatterns(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            // We assume that we have a restriction unless there are roles without restriction. This, we only have to check the roles
            // without restriction.
            for (String role : context.getMappedRoles()) {
                WildcardMatcher pattern = this.rolesToStaticIndexPatternWithoutRule.get(role);

                if (pattern != null && pattern.test(index)) {
                    return true;
                }
            }

            // If we found no roles without restriction, we assume a restriction
            return false;
        }

        boolean hasUnrestrictedPatternTemplates(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            // We assume that we have a restriction unless there are roles without restriction. This, we only have to check the roles
            // without restriction.
            for (String role : context.getMappedRoles()) {
                Set<IndexPattern> dynamicIndexPatternsWithoutRule = this.rolesToDynamicIndexPatternWithoutRule.get(role);

                if (dynamicIndexPatternsWithoutRule != null) {
                    for (IndexPattern indexPatternTemplate : dynamicIndexPatternsWithoutRule) {
                        try {
                            if (indexPatternTemplate.matches(index, context, context.getIndicesLookup())) {
                                return true;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            log.error("Error while matching index pattern of role {}", role, e);
                        }
                    }
                }
            }

            // If we found no roles without restriction, we assume a restriction
            return false;
        }

        /**
         * Only to be used if there is no stateful index information
         */
        boolean hasRestrictedPatterns(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            for (String role : context.getMappedRoles()) {
                Map<WildcardMatcher, SingleRule> indexPatternToRule = this.rolesToStaticIndexPatternToRule.get(role);

                if (indexPatternToRule != null) {
                    for (WildcardMatcher indexPattern : indexPatternToRule.keySet()) {
                        if (indexPattern.test(index)) {
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        boolean hasRestrictedPatternTemplates(PrivilegesEvaluationContext context, String index) throws PrivilegesEvaluationException {
            for (String role : context.getMappedRoles()) {
                Map<IndexPattern, SingleRule> dynamicIndexPatternToRule = this.rolesToDynamicIndexPatternToRule.get(role);

                if (dynamicIndexPatternToRule != null) {
                    for (IndexPattern indexPattern : dynamicIndexPatternToRule.keySet()) {
                        try {
                            if (indexPattern.matches(index, context, context.getIndicesLookup())) {
                                return true;
                            }
                        } catch (PrivilegesEvaluationException e) {
                            log.error("Error while matching index pattern of role {}", role, e);
                        }
                    }
                }
            }

            return false;
        }
    }

    static class StatefulRules<SingleRule> {
        final Map<String, IndexAbstraction> indexMetadata;

        final Map<String, Map<String, SingleRule>> indexToRoleToRule;
        final Map<String, Set<String>> indexToRoleWithoutRule;

        private final RoleToRuleFunction<SingleRule> roleToRuleFunction;

        StatefulRules(
            SecurityDynamicConfiguration<RoleV7> roles,
            Map<String, IndexAbstraction> indexMetadata,
            RoleToRuleFunction<SingleRule> roleToRuleFunction
        ) {
            this.roleToRuleFunction = roleToRuleFunction;
            this.indexMetadata = indexMetadata;

            DeduplicatingCompactSubSetBuilder<String> roleSetBuilder = new DeduplicatingCompactSubSetBuilder<>(
                roles.getCEntries().keySet()
            );
            CompactMapGroupBuilder<String, SingleRule> roleMapBuilder = new CompactMapGroupBuilder<>(roles.getCEntries().keySet());
            Map<String, DeduplicatingCompactSubSetBuilder.SubSetBuilder<String>> indexToRoleWithoutRule = new HashMap<>();
            Map<String, CompactMapGroupBuilder.MapBuilder<String, SingleRule>> indexToRoleToRule = new HashMap<>();

            for (Map.Entry<String, RoleV7> entry : roles.getCEntries().entrySet()) {
                try {
                    String roleName = entry.getKey();
                    RoleV7 role = entry.getValue();

                    roleSetBuilder.next(roleName);

                    for (RoleV7.Index indexPermissions : role.getIndex_permissions()) {
                        if (indexPermissions.getIndex_patterns().contains("*")) {
                            // Wildcard index patterns are handled in the static IndexPermissions object.
                            continue;
                        }

                        WildcardMatcher indexMatcher = IndexPattern.from(indexPermissions.getIndex_patterns()).getStaticPattern();

                        if (indexMatcher == WildcardMatcher.NONE) {
                            // The pattern is likely blank because there are only dynamic patterns.
                            // Dynamic index patterns are not handled here, but in the static IndexPermissions object
                            continue;
                        }

                        SingleRule rule = this.roleToRule(indexPermissions);

                        if (rule != null) {
                            for (String index : indexMatcher.iterateMatching(indexMetadata.keySet())) {
                                indexToRoleToRule.computeIfAbsent(index, k -> roleMapBuilder.createMapBuilder()).put(roleName, rule);
                            }
                        } else {
                            for (String index : indexMatcher.iterateMatching(indexMetadata.keySet())) {
                                indexToRoleWithoutRule.computeIfAbsent(index, k -> roleSetBuilder.createSubSetBuilder()).add(roleName);
                            }
                        }
                    }
                } catch (Exception e) {
                    log.error("Unexpected exception while processing role: {}\nIgnoring role.", entry, e);
                }
            }

            DeduplicatingCompactSubSetBuilder.Completed<String> completed = roleSetBuilder.build();

            this.indexToRoleToRule = indexToRoleToRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> entry.getValue().build()));
            this.indexToRoleWithoutRule = indexToRoleWithoutRule.entrySet()
                .stream()
                .collect(ImmutableMap.toImmutableMap(entry -> entry.getKey(), entry -> entry.getValue().build(completed)));

        }

        protected SingleRule roleToRule(RoleV7.Index rolePermissions) throws PrivilegesConfigurationValidationException {
            return this.roleToRuleFunction.apply(rolePermissions);
        }

        boolean covers(String index) {
            return this.indexMetadata.get(index) != null;
        }

    }

    @FunctionalInterface
    static interface RoleToRuleFunction<SingleRule> {
        SingleRule apply(RoleV7.Index indexPrivileges) throws PrivilegesConfigurationValidationException;
    }

    static abstract class Rule {
        abstract boolean isUnrestricted();
    }

}
