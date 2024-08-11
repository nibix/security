package org.opensearch.security.privileges.dlsfls;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.DiagnosingMatcher;
import org.hamcrest.Matcher;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.common.CheckedFunction;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BaseTermQueryBuilder;
import org.opensearch.index.query.MatchNoneQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;

import java.io.IOException;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Suite;

import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.privileges.ExpressionEvaluationException;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluationException;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.user.User;
import org.opensearch.security.util.MockIndexMetadataBuilder;
import org.opensearch.test.framework.TestSecurityConfig;


import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.opensearch.security.util.MockIndexMetadataBuilder.dataStreams;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        DocumentPrivilegesTest.IndicesAndAliases_getRestriction.class })
public class DocumentPrivilegesTest {

    static NamedXContentRegistry xContentRegistry = new NamedXContentRegistry(
            ImmutableList.of(new NamedXContentRegistry.Entry(QueryBuilder.class, new ParseField(TermQueryBuilder.NAME),
                    (CheckedFunction<XContentParser, TermQueryBuilder, IOException>) (p) -> TermQueryBuilder.fromXContent(p))));

    @RunWith(Parameterized.class)
    public static class IndicesAndAliases_getRestriction {
        final static Metadata INDEX_METADATA = //
                indices("index_a1", "index_a2", "index_b1", "index_b2")//
                        .alias("alias_a")
                        .of("index_a1", "index_a2")//
                        .build();

        final static ClusterState CLUSTER_STATE = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(INDEX_METADATA).build();

        final static IndexAbstraction.Index index_a1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a1");
        final static  IndexAbstraction.Index index_a2 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a2");
        final static  IndexAbstraction.Index index_b1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_b1");

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndexSpec indexSpec;
        final IndexAbstraction.Index index;
        final PrivilegesEvaluationContext context;
        final boolean dfmEmptyOverridesAll;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("dls_role_1")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
            } else if (userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else {
                fail("Missing case for " + userSpec);
            }
        }

        @Test
        public void wildcard_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*", "-index_b*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*", "-index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == index_a1 || index == index_a2) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == index_b1) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("index_a*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_b*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == index_a1 || index == index_a2) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == index_b1) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void indexPattern_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("index_*",
                            "-index_b*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_*",
                            "-index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == index_a1 || index == index_a2) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == index_b1) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1"))
                            .on("index_${user.attrs.attr_a}1"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("index_${user.attrs.attr_a}1"));

            DocumentPrivileges subject = createSubject(roleConfig);

            try {
                DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

                if (userSpec.roles.isEmpty()) {
                    assertThat(dlsRestriction, isFullyRestricted());
                } else if (index == index_a1) {
                    if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isUnrestricted());
                    }
                } else if (index == index_a2) {
                    if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isFullyRestricted());
                    } else if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == index_b1) {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } catch (PrivilegesEvaluationException e) {
                if ((userSpec.roles.contains("non_dls_role") || userSpec.roles.contains("dls_role_1"))
                        && !userSpec.attributes.containsKey("attr_a")) {
                    assertThat(e.getCause(), is(instanceOf((ExpressionEvaluationException.class))));
                } else {
                    fail("Unexpected exception: " + e);
                }
            }
        }

        @Test
        public void alias() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("alias_a"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a2"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("alias_a"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == index_a1) {
                if (userSpec.roles.contains("non_dls_role")) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isUnrestricted());
                }
            } else if (index == index_a2) {
                if (userSpec.roles.contains("non_dls_role")) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isUnrestricted());
                }
            } else if (index == index_b1) {
                assertThat(dlsRestriction, isFullyRestricted());
            }
        }



        @Parameterized.Parameters(name = "{0}; {1}; {2}; {3}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(//
                    new UserSpec("non_dls_role", "non_dls_role"), //
                    new UserSpec("dls_role_1", "dls_role_1"), //
                    new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                    new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                    new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("no roles")//
            )) {
                for (IndexSpec indexSpec : Arrays.asList(//
                        new IndexSpec("index_a1"), //
                        new IndexSpec("index_a2"), //
                        new IndexSpec("index_b1"))) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        for (DfmEmptyOverridesAll dfmEmptyOverridesAll : DfmEmptyOverridesAll.values()) {
                            result.add(new Object[] { userSpec, indexSpec, statefulness, dfmEmptyOverridesAll });
                        }
                    }
                }
            }
            return result;
        }

        public IndicesAndAliases_getRestriction(UserSpec userSpec, IndexSpec indexSpec, Statefulness statefulness, DfmEmptyOverridesAll dfmEmptyOverridesAll) {
            this.userSpec = userSpec;
            this.indexSpec = indexSpec;
            this.user = userSpec.buildUser();
            this.index = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(indexSpec.index);
            this.context = new PrivilegesEvaluationContext(this.user, ImmutableSet.copyOf(userSpec.roles), null, null, null, null, null, () -> CLUSTER_STATE);
            this.statefulness = statefulness;
            this.dfmEmptyOverridesAll = dfmEmptyOverridesAll == DfmEmptyOverridesAll.DFM_EMPTY_OVERRIDES_ALL_TRUE;
        }


        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(roleConfig, statefulness == Statefulness.STATEFUL ? INDEX_METADATA.getIndicesLookup() : null, xContentRegistry, Settings.builder().put("plugins.security.dfm_empty_overrides_all", this.dfmEmptyOverridesAll).build());
        }
    }

    /*
    @RunWith(Parameterized.class)
    public static class IndicesAndAliases_hasRestriction {
        final static Metadata INDEX_METADATA = //
                indices("index_a1", "index_a2", "index_b1", "index_b2")//
                        .alias("alias_a")
                        .of("index_a1", "index_a2")//
                        .build();

        final static IndexAbstraction.Index index_a1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a1");
        final static  IndexAbstraction.Index index_a2 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_a2");
        final static  IndexAbstraction.Index index_b1 = (IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get("index_b1");
        final static  IndexAbstraction.Alias alias_a = (IndexAbstraction.Alias) INDEX_METADATA.getIndicesLookup().get("alias_a");

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndicesSpec indicesSpec;
        final ResolvedIndices resolvedIndices;
        final PrivilegesEvaluationContext context;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void wildcard_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*", "-index_b*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*", "-index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("index_a*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_b*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = new DocumentPrivileges(roleConfig, BASIC, MetricsLevel.NONE);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void indexPattern_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("index_*",
                            "-index_b*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_*",
                            "-index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1"))
                            .on("index_${user.attrs.attr_a}1"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("index_${user.attrs.attr_a}1"));

            DocumentPrivileges subject = createSubject(roleConfig);

            try {
                boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

                if (userSpec.roles.contains("non_dls_role") && resolvedIndices.getLocal().getUnion().equals(ImmutableSet.of(index_a1))
                        && userSpec.attributes.containsKey("attr_a")) {
                    assertFalse(result);
                } else {
                    assertTrue(result);
                }
            } catch (PrivilegesEvaluationException e) {
                if ((userSpec.roles.contains("non_dls_role") || userSpec.roles.contains("dls_role_1"))
                        && !userSpec.attributes.containsKey("attr_a")) {
                    assertThat(e.getCause(), is(instanceOf((ExpressionEvaluationException.class))));
                } else {
                    fail("Unexpected exception: " + e);
                }
            }
        }

        @Test
        public void alias_static() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("alias_a"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("alias_a"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")
                    && resolvedIndices.getLocal().getUnion().forAllApplies(i -> i instanceof Meta.Alias || !i.parentAliases().isEmpty())) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void alias_static_wildcardNonDls() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("alias_a"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role") && resolvedIndices.getLocal().getUnion().forAllApplies(i -> !i.parentAliases().isEmpty() || i instanceof Meta.Alias)) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void alias_wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("alias_a*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("alias_a*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

            if (userSpec.roles.contains("non_dls_role")
                    && resolvedIndices.getLocal().getUnion().forAllApplies(i -> i == alias_a || i.parentAliases().contains(alias_a))) {
                assertFalse(result);
            } else {
                assertTrue(result);
            }
        }

        @Test
        public void alias_template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1"))
                            .on("alias_${user.attrs.attr_a}"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("index_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("alias_${user.attrs.attr_a}"));

            DocumentPrivileges subject = createSubject(roleConfig);

            try {
                boolean result = subject.hasRestrictions(context, resolvedIndices, Meter.NO_OP);

                if (userSpec.roles.contains("non_dls_role") && userSpec.attributes.containsKey("attr_a")
                        && resolvedIndices.getLocal().getUnion().forAllApplies(i -> i == alias_a || i.parentAliases().contains(alias_a))) {
                    assertFalse(result);
                } else {
                    assertTrue(result);
                }
            } catch (PrivilegesEvaluationException e) {
                if ((userSpec.roles.contains("non_dls_role") || userSpec.roles.contains("dls_role_1"))
                        && !userSpec.attributes.containsKey("attr_a")) {
                    assertThat(e.getCause(), is(instanceOf((ExpressionEvaluationException.class))));
                } else {
                    fail("Unexpected exception: " + e);
                }
            }
        }

        @Parameters(name = "{0}; {1}; {2}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(//
                    new UserSpec("non_dls_role", "non_dls_role"), //
                    new UserSpec("dls_role_1", "dls_role_1"), //
                    new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                    new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                    new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("no roles")//
            )) {
                for (IndicesSpec indicesSpec : Arrays.asList(//
                        new IndicesSpec("index_a1"), //
                        new IndicesSpec("index_a2"), //
                        new IndicesSpec("index_b1"), //
                        new IndicesSpec("alias_a"), //
                        new IndicesSpec("index_a1", "index_a2"), //
                        new IndicesSpec("index_a1", "index_b1"), //
                        new IndicesSpec("alias_a", "index_b1"))) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        result.add(new Object[] { userSpec, indicesSpec, statefulness });
                    }
                }
            }
            return result;
        }

        public IndicesAndAliases_hasRestriction(UserSpec userSpec, IndicesSpec indicesSpec, Statefulness statefulness) {
            this.userSpec = userSpec;
            this.indicesSpec = indicesSpec;
            this.user = userSpec.buildUser();
            this.resolvedIndices = ResolvedIndices.of(BASIC, indicesSpec.indices.toArray(new String[0]));
            this.context = new PrivilegesEvaluationContext(this.user, false, ImmutableSet.of(userSpec.roles), null, null, true, null, null);
            this.statefulness = statefulness;
        }

        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(roleConfig, statefulness == Statefulness.STATEFUL ? BASIC : null, MetricsLevel.NONE);
        }
    }

    @RunWith(Parameterized.class)
    public static class DataStreams_getRestriction {
        final static Metadata INDEX_METADATA = dataStreams("datastream_a1", "datastream_a2", "datastream_b1", "datastream_b2")
                .alias("alias_a").of("datastream_a1", "datastream_a2").build();

        final static IndexAbstraction.Index datastream_a1_backing = ( IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(".ds-datastream_a1_ßß0001");
        final static IndexAbstraction.Index datastream_a2_backing = ( IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(".ds-datastream_a2_000001");
        final static IndexAbstraction.Index datastream_b1_backing = ( IndexAbstraction.Index) INDEX_METADATA.getIndicesLookup().get(".ds-datastream_b1_000001");

        final Statefulness statefulness;
        final UserSpec userSpec;
        final User user;
        final IndexSpec indexSpec;
        final IndexAbstraction.Index index;
        final PrivilegesEvaluationContext context;

        @Test
        public void wildcard() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                    new TestSecurityConfig.Role("non_dls_role").dataStreamPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("dls_role_1")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
            } else if (userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
            } else {
                fail("Unhandled case " + userSpec);
            }
        }

        @Test
        public void wildcard_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*",
                            "-datastream_b*"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*",
                            "-datastream_a*"),
                    new TestSecurityConfig.Role("non_dls_role").dataStreamPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == datastream_a1_backing || index == datastream_a2_backing) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == datastream_b1_backing) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void indexPattern() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("datastream_a*"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("datastream_b*"),
                    new TestSecurityConfig.Role("non_dls_role").dataStreamPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == datastream_a1_backing || index == datastream_a2_backing) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == datastream_b1_backing) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void indexPattern_negation() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("datastream_*",
                            "-datastream_b*"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("datastream_*",
                            "-datastream_a*"),
                    new TestSecurityConfig.Role("non_dls_role").dataStreamPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == datastream_a1_backing || index == datastream_a2_backing) {
                if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } else if (index == datastream_b1_backing) {
                if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            }
        }

        @Test
        public void template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1"))
                            .on("datastream_${user.attrs.attr_a}1"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("datastream_a*"),
                    new TestSecurityConfig.Role("non_dls_role").dataStreamPermissions("*").on("datastream_${user.attrs.attr_a}1"));

            DocumentPrivileges subject = createSubject(roleConfig);

            try {
                DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

                if (userSpec.roles.isEmpty()) {
                    assertThat(dlsRestriction, isFullyRestricted());
                } else if (index == datastream_a1_backing) {
                    if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == datastream_a2_backing) {
                    if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else {
                        assertThat(dlsRestriction, isFullyRestricted());
                    }
                } else if (index == datastream_b1_backing) {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } catch (PrivilegesEvaluationException e) {
                if ((userSpec.roles.contains("non_dls_role") || userSpec.roles.contains("dls_role_1"))
                        && !userSpec.attributes.containsKey("attr_a")) {
                    assertThat(e.getCause(), is(instanceOf((ExpressionEvaluationException.class))));
                } else {
                    fail("Unexpected exception: " + e);
                }
            }
        }

        @Test
        public void alias_static() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("alias_a"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("datastream_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("alias_a"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (index == datastream_a1_backing) {
                if (userSpec.roles.contains("non_dls_role")) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else {
                    assertThat(dlsRestriction, isUnrestricted());
                }
            } else if (index == datastream_a2_backing) {
                if (userSpec.roles.contains("non_dls_role")) {
                    assertThat(dlsRestriction, isUnrestricted());
                } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                } else if (userSpec.roles.contains("dls_role_1")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                } else if (userSpec.roles.contains("dls_role_2")) {
                    assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                } else {
                    assertThat(dlsRestriction, isUnrestricted());
                }
            } else if (index == datastream_b1_backing) {
                assertThat(dlsRestriction, isFullyRestricted());
            }
        }

        @Test
        public void alias_template() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").aliasPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1"))
                            .on("alias_${user.attrs.attr_a}"),
                    new TestSecurityConfig.Role("dls_role_2").dataStreamPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("datastream_a2"),
                    new TestSecurityConfig.Role("non_dls_role").aliasPermissions("*").on("alias_${user.attrs.attr_a}"));

            DocumentPrivileges subject = createSubject(roleConfig);

            try {
                DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

                if (userSpec.roles.isEmpty()) {
                    assertThat(dlsRestriction, isFullyRestricted());
                } else if (index == datastream_a1_backing) {
                    if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else {
                        fail("Unhandled case " + userSpec);
                    }
                } else if (index == datastream_a2_backing) {
                    if (userSpec.roles.contains("non_dls_role")) {
                        assertThat(dlsRestriction, isUnrestricted());
                    } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
                    } else if (userSpec.roles.contains("dls_role_1")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
                    } else if (userSpec.roles.contains("dls_role_2")) {
                        assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
                    } else {
                        fail("Unhandled case " + userSpec);
                    }
                } else if (index == datastream_b1_backing) {
                    assertThat(dlsRestriction, isFullyRestricted());
                }
            } catch (PrivilegesEvaluationException e) {
                if ((userSpec.roles.contains("non_dls_role") || userSpec.roles.contains("dls_role_1"))
                        && !userSpec.attributes.containsKey("attr_a")) {
                    assertThat(e.getCause(), is(instanceOf((ExpressionEvaluationException.class))));
                } else {
                    fail("Unexpected exception: " + e);
                }
            }
        }

        @Test
        public void wildcardOnIndices() throws Exception {
            SecurityDynamicConfiguration<RoleV7> roleConfig = roleConfig(//
                    new TestSecurityConfig.Role("dls_role_1").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r1")).on("*"),
                    new TestSecurityConfig.Role("dls_role_2").indexPermissions("*").dls(QueryBuilders.termQuery("dept", "dept_r2")).on("*"),
                    new TestSecurityConfig.Role("non_dls_role").indexPermissions("*").on("*"));
            DocumentPrivileges subject = createSubject(roleConfig);

            DlsRestriction dlsRestriction = subject.getRestriction(context, index.getName());

            if (userSpec.roles.isEmpty()) {
                assertThat(dlsRestriction, isFullyRestricted());
            } else if (userSpec.roles.contains("non_dls_role")) {
                assertThat(dlsRestriction, isUnrestricted());
            } else if (userSpec.roles.contains("dls_role_1") && userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1"), termQuery("dept", "dept_r2")));
            } else if (userSpec.roles.contains("dls_role_1")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r1")));
            } else if (userSpec.roles.contains("dls_role_2")) {
                assertThat(dlsRestriction, isRestricted(termQuery("dept", "dept_r2")));
            }
        }

        @Parameters(name = "{0}; {1}; {2}")
        public static Collection<Object[]> params() {
            List<Object[]> result = new ArrayList<>();

            for (UserSpec userSpec : Arrays.asList(//
                    new UserSpec("non_dls_role", "non_dls_role"), //
                    new UserSpec("dls_role_1", "dls_role_1"), //
                    new UserSpec("dls_role_1 and dls_role_2", "dls_role_1", "dls_role_2"), //
                    new UserSpec("dls_role_1 and non_dls_role", "dls_role_1", "non_dls_role"), //
                    new UserSpec("non_dls_role, attributes", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1, attributes", "dls_role_1").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and dls_role_2, attributes", "dls_role_1", "dls_role_2").attribute("attr_a", "a"), //
                    new UserSpec("dls_role_1 and non_dls_role, attributes", "dls_role", "non_dls_role").attribute("attr_a", "a"), //
                    new UserSpec("no roles")//
            )) {
                for (IndexSpec indexSpec : Arrays.asList(//
                        new IndexSpec(datastream_a1_backing), //
                        new IndexSpec(datastream_a2_backing), //
                        new IndexSpec(datastream_b1_backing.name()))) {
                    for (Statefulness statefulness : Statefulness.values()) {
                        result.add(new Object[] { userSpec, indexSpec, statefulness });
                    }
                }
            }
            return result;
        }

        private DocumentPrivileges createSubject(SecurityDynamicConfiguration<RoleV7> roleConfig) {
            return new DocumentPrivileges(roleConfig, statefulness == Statefulness.STATEFUL ? BASIC : null, MetricsLevel.NONE);
        }

        public DataStreams_getRestriction(UserSpec userSpec, IndexSpec indexSpec, Statefulness statefulness) {
            this.userSpec = userSpec;
            this.indexSpec = indexSpec;
            this.user = userSpec.buildUser();
            this.index = indexSpec.index;
            this.context = new PrivilegesEvaluationContext(this.user, false, ImmutableSet.of(userSpec.roles), null, null, true, null, null);
            this.statefulness = statefulness;
        }

    }*/

    static SecurityDynamicConfiguration<RoleV7> roleConfig(TestSecurityConfig.Role... roles) {
        return TestSecurityConfig.Role.toRolesConfiguration(roles);
    }

    public static class UserSpec {
        final List<String> roles;
        final String description;
        final Map<String, String> attributes = new HashMap<>();

        UserSpec(String description, String... roles) {
            this.description = description;
            this.roles = Arrays.asList(roles);
        }

        UserSpec attribute(String name, String value) {
            this.attributes.put(name, value);
            return this;
        }

        User buildUser() {
            User user = new User("test_user_" + description);
            user.addAttributes(this.attributes);
            return user;
        }

        @Override
        public String toString() {
            return this.description;
        }
    }

    public static class IndexSpec {
        final String index;

        IndexSpec(String index) {
            this.index = index;
        }

        @Override
        public String toString() {
            return this.index;
        }
    }

    public static class IndicesSpec {
        final ImmutableList<String> indices;

        IndicesSpec(String... indices) {
            this.indices = ImmutableList.copyOf(indices);
        }

        @Override
        public String toString() {
            return this.indices.toString();
        }
    }

    static enum Statefulness {
        STATEFUL, NON_STATEFUL
    }

    static enum DfmEmptyOverridesAll {
        DFM_EMPTY_OVERRIDES_ALL_TRUE,
        DFM_EMPTY_OVERRIDES_ALL_FALSE
    }

    static DiagnosingMatcher<DlsRestriction> isUnrestricted() {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has no restrictions");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.isUnrestricted()) {
                    return true;
                } else {
                    mismatchDescription.appendText("The DlsRestriction object is not unrestricted:").appendValue(dlsRestriction);
                    return false;
                }
            }

        };

    }

    static DiagnosingMatcher<DlsRestriction> isRestricted() {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has at least one restrictions");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (!dlsRestriction.isUnrestricted()) {
                    return true;
                } else {
                    mismatchDescription.appendText("The DlsRestriction object is not restricted:").appendValue(dlsRestriction);
                    return false;
                }
            }
        };
    }

    @SafeVarargs
    static DiagnosingMatcher<DlsRestriction> isRestricted(Matcher<QueryBuilder>... queries) {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has the restrictions: ").appendList("", "", ", ", Arrays.asList(queries));
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.isUnrestricted()) {
                    mismatchDescription.appendText("The DlsRestriction object is not restricted:").appendValue(dlsRestriction);
                    return false;

                }

                Set<Matcher<QueryBuilder>> subMatchers = new HashSet<>(Arrays.asList(queries));
                Set<QueryBuilder> unmatchedQueries = new HashSet<>(dlsRestriction.getQueries());

                for (QueryBuilder query : dlsRestriction.getQueries()) {
                    for (Matcher<QueryBuilder> subMatcher : subMatchers) {
                        if (subMatcher.matches(query)) {
                            unmatchedQueries.remove(query);
                            subMatchers.remove(subMatcher);
                            break;
                        }
                    }
                }

                if (unmatchedQueries.isEmpty() && subMatchers.isEmpty()) {
                    return true;
                }

                if (!unmatchedQueries.isEmpty()) {
                    mismatchDescription.appendText("The DlsRestriction contains unexpected queries:").appendValue(unmatchedQueries).appendText("\n");
                }

                if (!subMatchers.isEmpty()) {
                    mismatchDescription.appendText("The DlsRestriction does not contain expected queries: ").appendValue(subMatchers)
                            .appendText("\n");
                }

                return false;
            }

        };
    }

    static DiagnosingMatcher<DlsRestriction> isFullyRestricted() {
        return new DiagnosingMatcher<DlsRestriction>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A DlsRestriction object that has full restrictions");
            }

            @Override
            protected boolean matches(Object item, Description mismatchDescription) {
                if (!(item instanceof DlsRestriction)) {
                    mismatchDescription.appendValue(item).appendText(" is not a DlsRestriction object");
                    return false;
                }

                DlsRestriction dlsRestriction = (DlsRestriction) item;

                if (dlsRestriction.getQueries().size() != 0) {
                    for (QueryBuilder query : dlsRestriction.getQueries()) {
                        if (!query.equals(new MatchNoneQueryBuilder())) {
                            mismatchDescription.appendText("The DlsRestriction object is not fully restricted:").appendValue(dlsRestriction);
                            return false;
                        }
                    }

                    return true;
                } else {
                    mismatchDescription.appendText("The DlsRestriction object is not fully restricted:").appendValue(dlsRestriction);
                    return false;
                }
            }

        };

    }

    static BaseMatcher<QueryBuilder> termQuery(String field, Object value) {
        return new BaseMatcher<QueryBuilder>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("A TermQueryBuilder object with ").appendValue(field).appendText("=").appendValue(value);
            }

            @Override
            public boolean matches(Object item) {
                if (!(item instanceof BaseTermQueryBuilder)) {
                    return false;
                }

                BaseTermQueryBuilder<?> queryBuilder = (BaseTermQueryBuilder<?>) item;

                if (queryBuilder.fieldName().equals(field) && queryBuilder.value().equals(value)) {
                    return true;
                } else {
                    return false;
                }
            }

        };

    }

}
