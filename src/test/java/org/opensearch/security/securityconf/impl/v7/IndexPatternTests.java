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

package org.opensearch.security.securityconf.impl.v7;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeMap;

import com.google.common.collect.ImmutableSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.support.IndicesOptions;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexAbstraction.Type;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.security.securityconf.ConfigModelV7.IndexPattern;
import org.opensearch.security.user.User;

import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@RunWith(MockitoJUnitRunner.class)
public class IndexPatternTests {

    @Mock
    private User user;
    @Mock
    private IndexNameExpressionResolver resolver;
    @Mock
    private ClusterService clusterService;

    private IndexPattern ip;

    @Before
    public void before() {
        ip = spy(new IndexPattern("defaultPattern"));
    }

    @After
    public void after() {
        verifyNoMoreInteractions(user, resolver, clusterService);
    }

    @Test
    public void testCtor() {
        assertThrows(NullPointerException.class, () -> new IndexPattern(null));
    }




    private ClusterState createClusterState(final IndexShorthand... indices) {
        final TreeMap<String, IndexAbstraction> indexMap = new TreeMap<String, IndexAbstraction>();
        Arrays.stream(indices).forEach(indexShorthand -> {
            final IndexAbstraction indexAbstraction = mock(IndexAbstraction.class);
            when(indexAbstraction.getType()).thenReturn(indexShorthand.type);
            indexMap.put(indexShorthand.name, indexAbstraction);
        });

        final Metadata mockMetadata = mock(Metadata.class, withSettings().strictness(Strictness.LENIENT));
        when(mockMetadata.getIndicesLookup()).thenReturn(indexMap);

        final ClusterState mockClusterState = mock(ClusterState.class, withSettings().strictness(Strictness.LENIENT));
        when(mockClusterState.getMetadata()).thenReturn(mockMetadata);

        return mockClusterState;
    }

    private class IndexShorthand {
        public final String name;
        public final Type type;

        public IndexShorthand(final String name, final Type type) {
            this.name = name;
            this.type = type;
        }
    }
}
