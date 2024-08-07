package org.opensearch.security.privileges;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.security.support.WildcardMatcher;

/**
 * Aggregates index patterns defined in roles and segments them into patterns using template expressions ("index_${user.name}"),
 * patterns using date math and plain patterns. This segmentation is needed because only plain patterns can be used
 * to pre-compute privilege maps. The other types of patterns need to be evaluated "live" during the actual request.
 */
public class IndexPattern {
    private static final Logger log = LogManager.getLogger(IndexPattern.class);

    /**
     * An IndexPattern which does not match any index.
     */
    public static final IndexPattern EMPTY = new IndexPattern(null, ImmutableList.of(), ImmutableList.of());

    private final WildcardMatcher staticPattern;
    private final ImmutableList<String> patternTemplates;
    private final ImmutableList<String> dateMathExpressions;
    private final int hashCode;

    public IndexPattern(WildcardMatcher staticPattern, ImmutableList<String> patternTemplates, ImmutableList<String> dateMathExpressions) {
        this.staticPattern = staticPattern;
        this.patternTemplates = patternTemplates;
        this.dateMathExpressions = dateMathExpressions;
        this.hashCode = (staticPattern != null ? staticPattern.hashCode() : 0) + patternTemplates.hashCode() + dateMathExpressions
            .hashCode();
    }

    public boolean matches(String index, PrivilegesEvaluationContext context, Map<String, IndexAbstraction> indexMetadata)
        throws PrivilegesEvaluationException {
        if (staticPattern != null && staticPattern.test(index)) {
            return true;
        }

        if (!patternTemplates.isEmpty()) {
            for (String patternTemplate : this.patternTemplates) {
                try {
                    WildcardMatcher matcher = context.getRenderedMatcher(patternTemplate);

                    if (matcher.test(index)) {
                        return true;
                    }
                } catch (ExpressionEvaluationException e) {
                    throw new PrivilegesEvaluationException("Error while evaluating dynamic index pattern: " + patternTemplate, e);
                }
            }
        }

        if (!dateMathExpressions.isEmpty()) {
            IndexNameExpressionResolver indexNameExpressionResolver = context.getIndexNameExpressionResolver();

            // Note: The use of date math expressions in privileges is a bit odd, as it only provides a very limited
            // solution for the potential user case. A different approach might be nice.

            for (String dateMathExpression : this.dateMathExpressions) {
                try {
                    String resolvedExpression = indexNameExpressionResolver.resolveDateMathExpression(dateMathExpression);

                    if (!containsPlaceholder(resolvedExpression)) {
                        WildcardMatcher matcher = WildcardMatcher.from(resolvedExpression);

                        if (matcher.test(index)) {
                            return true;
                        }
                    } else {
                        WildcardMatcher matcher = context.getRenderedMatcher(resolvedExpression);

                        if (matcher.test(index)) {
                            return true;
                        }
                    }
                } catch (Exception e) {
                    throw new PrivilegesEvaluationException("Error while evaluating date math expression: " + dateMathExpression, e);
                }
            }
        }

        IndexAbstraction indexAbstraction = indexMetadata.get(index);

        if (indexAbstraction instanceof IndexAbstraction.Index) {
            // Check for the privilege for aliases or data streams containing this index

            if (indexAbstraction.getParentDataStream() != null) {
                if (matches(indexAbstraction.getParentDataStream().getName(), context, indexMetadata)) {
                    return true;
                }
            }

            // Retrieve aliases: The use of getWriteIndex() is a bit messy, but it is the only way to access
            // alias metadata from here.
            for (String alias : indexAbstraction.getWriteIndex().getAliases().keySet()) {
                if (matches(alias, context, indexMetadata)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String toString() {
        if (staticPattern != null && patternTemplates != null && patternTemplates.size() != 0) {
            return staticPattern + " " + patternTemplates;
        } else if (staticPattern != null) {
            return staticPattern.toString();
        } else if (patternTemplates != null) {
            return patternTemplates.toString();
        } else {
            return "-/-";
        }
    }

    public WildcardMatcher getStaticPattern() {
        return staticPattern;
    }

    public boolean hasStaticPattern() {
        return staticPattern != null && staticPattern != WildcardMatcher.NONE;
    }

    public boolean hasDynamicPattern() {
        return !patternTemplates.isEmpty() || !dateMathExpressions.isEmpty();
    }

    public IndexPattern dynamicOnly() {
        if (patternTemplates.isEmpty() && dateMathExpressions.isEmpty()) {
            return EMPTY;
        } else {
            return new IndexPattern(null, this.patternTemplates, this.dateMathExpressions);
        }
    }

    public boolean isEmpty() {
        return (staticPattern == null || staticPattern == WildcardMatcher.NONE)
            && this.patternTemplates.isEmpty()
            && this.dateMathExpressions.isEmpty();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof IndexPattern that)) return false;
        return Objects.equals(staticPattern, that.staticPattern)
            && Objects.equals(patternTemplates, that.patternTemplates)
            && Objects.equals(dateMathExpressions, that.dateMathExpressions);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    static class Builder {
        private List<WildcardMatcher> constantPatterns = new ArrayList<>();
        private List<String> patternTemplates = new ArrayList<>();
        private List<String> dateMathExpressions = new ArrayList<>();
        private int initializationErrors = 0;

        void add(List<String> source) {
            for (int i = 0; i < source.size(); i++) {
                try {
                    String indexPattern = source.get(i);

                    if (indexPattern.startsWith("<") && indexPattern.endsWith(">")) {
                        this.dateMathExpressions.add(indexPattern);
                    } else if (!containsPlaceholder(indexPattern)) {
                        this.constantPatterns.add(WildcardMatcher.from(indexPattern));
                    } else {
                        this.patternTemplates.add(indexPattern);
                    }
                } catch (Exception e) {
                    // This usually happens when the index pattern defines an unparseable regular expression
                    log.error("Error while creating index pattern for {}", source, e);
                    this.initializationErrors++;
                }
            }
        }

        IndexPattern build() {
            return new IndexPattern(
                WildcardMatcher.from(constantPatterns),
                ImmutableList.copyOf(patternTemplates),
                ImmutableList.copyOf(dateMathExpressions)
            );
        }
    }

    static boolean containsPlaceholder(String indexPattern) {
        return indexPattern.indexOf("${") != -1;
    }

    public static IndexPattern from(List<String> source) {
        Builder builder = new Builder();
        builder.add(source);
        return builder.build();
    }
}
