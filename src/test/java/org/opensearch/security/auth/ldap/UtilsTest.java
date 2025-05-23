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

package org.opensearch.security.auth.ldap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class UtilsTest {

    @Test
    public void testLDAPName() throws Exception {
        // same ldapname
        assertThat(new LdapName("CN=1,OU=2,O=3,C=4"), is(new LdapName("CN=1,OU=2,O=3,C=4")));

        // case differ
        assertThat(new LdapName("CN=1,OU=2,O=3,C=4".toUpperCase()), is(new LdapName("CN=1,OU=2,O=3,C=4".toLowerCase())));

        // case differ
        assertThat(new LdapName("CN=abc,OU=xyz,O=3,C=4".toUpperCase()), is(new LdapName("CN=abc,OU=xyz,O=3,C=4".toLowerCase())));

        // same ldapname
        assertThat(new LdapName("CN=A,OU=2,O=3,C=XxX"), is(new LdapName("CN=a,OU=2,O=3,C=xxx")));

        // case differ and spaces
        assertThat(new LdapName("CN= 1,Ou=2,O=3,c=4"), is(new LdapName("Cn =1 ,OU=2, O = 3,C=4")));

        // same components, different order
        Assert.assertNotEquals(new LdapName("CN=1,OU=2,C=4,O=3"), new LdapName("CN=1,OU=2,O=3,C=4"));

        // last component missing
        Assert.assertNotEquals(new LdapName("CN=1,OU=2,O=3"), new LdapName("CN=1,OU=2,O=3,C=4"));

        // first component missing
        Assert.assertNotEquals(new LdapName("OU=2,O=3,C=4"), new LdapName("CN=1,OU=2,O=3,C=4"));

        // parse exception
        try {
            new LdapName("OU2,O=3,C=4");
            Assert.fail();
        } catch (InvalidNameException e) {
            // expected
        }
    }
}
