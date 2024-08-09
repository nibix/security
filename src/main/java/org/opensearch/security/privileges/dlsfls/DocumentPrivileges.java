package org.opensearch.security.privileges.dlsfls;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.AbstractQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.security.privileges.PrivilegesConfigurationValidationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.privileges.UserAttributes;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

public class DocumentPrivileges extends AbstractRuleBasedPrivileges<DocumentPrivileges.DlsQuery, DlsRestriction> {

    private final NamedXContentRegistry xContentRegistry;

    public DocumentPrivileges(
        SecurityDynamicConfiguration<RoleV7> roles,
        Map<String, IndexAbstraction> indexMetadata,
        NamedXContentRegistry xContentRegistry,
        Settings settings
    ) {
        super(roles, indexMetadata, (rolePermissions) -> roleToRule(rolePermissions, xContentRegistry), settings);
        this.xContentRegistry = xContentRegistry;
    }

    static DlsQuery roleToRule(RoleV7.Index rolePermissions, NamedXContentRegistry xContentRegistry)
        throws PrivilegesConfigurationValidationException {
        String dlsQueryTemplate = rolePermissions.getDls();

        if (dlsQueryTemplate != null) {
            return DlsQuery.create(dlsQueryTemplate, xContentRegistry);
        } else {
            return null;
        }
    }

    @Override
    protected DlsRestriction unrestricted() {
        return DlsRestriction.NONE;
    }

    @Override
    protected DlsRestriction fullyRestricted() {
        return DlsRestriction.FULL;
    }

    @Override
    protected DlsRestriction compile(PrivilegesEvaluationContext context, Collection<DlsQuery> rules) throws PrivilegesEvaluationException {
        List<QueryBuilder> renderedQueries = new ArrayList<>(rules.size());

        for (DlsQuery query : rules) {
            renderedQueries.add(query.evaluate(context));
        }

        return new DlsRestriction(renderedQueries);
    }

    static abstract class DlsQuery {
        final String queryString;

        DlsQuery(String queryString) {
            this.queryString = queryString;
        }

        abstract QueryBuilder evaluate(PrivilegesEvaluationContext context) throws PrivilegesEvaluationException;

        @Override
        public int hashCode() {
            return queryString.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof DlsQuery)) {
                return false;
            }
            DlsQuery other = (DlsQuery) obj;
            if (queryString == null) {
                if (other.queryString != null) {
                    return false;
                }
            } else if (!queryString.equals(other.queryString)) {
                return false;
            }
            return true;
        }

        static DlsQuery create(String queryString, NamedXContentRegistry xContentRegistry)
            throws PrivilegesConfigurationValidationException {
            if (queryString.contains("${")) {
                return new DlsQuery.Dynamic(queryString, xContentRegistry);
            } else {
                return new DlsQuery.Constant(queryString, xContentRegistry);
            }
        }

        static class Constant extends DlsQuery {
            private final QueryBuilder queryBuilder;

            Constant(String queryString, NamedXContentRegistry xContentRegistry) throws PrivilegesConfigurationValidationException {
                super(queryString);
                try {
                    XContentParser parser = JsonXContent.jsonXContent.createParser(
                        xContentRegistry,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        queryString
                    );
                    this.queryBuilder = AbstractQueryBuilder.parseInnerQueryBuilder(parser);
                } catch (Exception e) {
                    throw new PrivilegesConfigurationValidationException("Invalid DLS query: " + queryString, e);
                }
            }

            @Override
            QueryBuilder evaluate(PrivilegesEvaluationContext context) {
                return queryBuilder;
            }
        }

        static class Dynamic extends DlsQuery {
            private final NamedXContentRegistry xContentRegistry;

            Dynamic(String queryString, NamedXContentRegistry xContentRegistry) {
                super(queryString);
                this.xContentRegistry = xContentRegistry;
            }

            @Override
            QueryBuilder evaluate(PrivilegesEvaluationContext context) throws PrivilegesEvaluationException {
                String effectiveQueryString = UserAttributes.replaceProperties(this.queryString, context);

                try {
                    XContentParser parser = JsonXContent.jsonXContent.createParser(
                        xContentRegistry,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        effectiveQueryString
                    );
                    return AbstractQueryBuilder.parseInnerQueryBuilder(parser);
                } catch (Exception e) {
                    throw new PrivilegesEvaluationException("Invalid DLS query: " + effectiveQueryString, e);
                }
            }
        }
    }

}
