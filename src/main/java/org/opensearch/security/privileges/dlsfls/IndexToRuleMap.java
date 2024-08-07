package org.opensearch.security.privileges.dlsfls;

import com.google.common.collect.ImmutableMap;

import java.util.function.Predicate;

/**
 * Maps index names to DLS/FLS/FM rules.
 * <p>
 * This only contains index names, not any alias or data stream names.
 * <p>
 * This map should be only used when really necessary, as computing a whole map of indices can be expensive.
 * It should be preferred to directly query the privilege status of indices using the getRestriction() methods
 * of the sub-classes of AbstractRuleBasedPrivileges.
 */
public class IndexToRuleMap<Rule> {
    private static final IndexToRuleMap<?> UNRESTRICTED = new IndexToRuleMap<Object>(ImmutableMap.of());

    private final ImmutableMap<String, Rule> indexMap;

    IndexToRuleMap(ImmutableMap<String, Rule> indexMap) {
        this.indexMap = indexMap;
    }

    public boolean isUnrestricted() {
        return this.indexMap.isEmpty();
    }

    public ImmutableMap<String, Rule> getIndexMap() {
        return indexMap;
    }

    public boolean containsAny(Predicate<Rule> predicate) {
        if (indexMap.isEmpty()) {
            return false;
        }

        for (Rule rule : this.indexMap.values()) {
            if (predicate.test(rule)) {
                return true;
            }
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public static <Rule> IndexToRuleMap<Rule> unrestricted() {
        return (IndexToRuleMap<Rule>) UNRESTRICTED;
    }
}
