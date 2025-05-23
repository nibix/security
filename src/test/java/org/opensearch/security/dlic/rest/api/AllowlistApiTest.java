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

package org.opensearch.security.dlic.rest.api;

import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableMap;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hc.core5.http.Header;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.auditlog.impl.AuditMessage;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.rest.RestHelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ADMIN_ENABLED;
import static org.junit.Assert.assertTrue;

/**
 * Testing class to verify that {@link AllowlistApiAction} works correctly.
 * Check {@link SecurityRestFilter} for extra tests for allowlisting functionality.
 */
public class AllowlistApiTest extends AbstractRestApiUnitTest {
    private RestHelper.HttpResponse response;

    /**
     * admin_all_access is a user who has all permissions - essentially an admin user, not the same as superadmin.
     * superadmin is identified by a certificate that should be passed as a part of the request header.
     */
    private final Header adminCredsHeader = encodeBasicHeader("admin_all_access", "admin_all_access");
    private final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

    private final String ENDPOINT = "/_plugins/_security/api/allowlist";

    /**
     * Helper function to test the GET and PUT endpoints.
     *
     * @throws Exception
     */
    private void checkGetAndPutAllowlistPermissions(final int expectedStatus, final boolean sendAdminCertificate, final Header... headers)
        throws Exception {

        final boolean prevSendAdminCertificate = rh.sendAdminCertificate;
        rh.sendAdminCertificate = sendAdminCertificate;

        // CHECK GET REQUEST
        response = rh.executeGetRequest(ENDPOINT, headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            // Note: the response has no whitespaces, so the .json file does not have whitespaces
            assertThat(
                FileHelper.loadFile("restapi/allowlist_response_success.json"),
                is(FileHelper.loadFile("restapi/allowlist_response_success.json"))
            );
        }
        // FORBIDDEN FOR NON SUPER ADMIN
        if (expectedStatus == HttpStatus.SC_FORBIDDEN) {
            assertTrue(response.getBody().contains("Access denied"));
        }
        // CHECK PUT REQUEST
        response = rh.executePutRequest(
            ENDPOINT,
            "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}",
            headers
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        rh.sendAdminCertificate = prevSendAdminCertificate;
    }

    @Test
    public void testResponseDoesNotContainMetaHeader() throws Exception {

        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executeGetRequest(ENDPOINT);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        Assert.assertFalse(response.getHeaders().contains("_meta"));
    }

    @Test
    public void testPutUnknownKey() throws Exception {

        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest(
            ENDPOINT,
            "{ \"unknownkey\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}"
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertTrue(response.getBody().contains("invalid_keys"));
        assertHealthy();
    }

    @Test
    public void testPutInvalidJson() throws Exception {
        setup();

        rh.sendAdminCertificate = true;
        RestHelper.HttpResponse response = rh.executePutRequest(
            ENDPOINT,
            "{ \"invalid\"::{{ [\"*\"], \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"GET\"] }}"
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        assertHealthy();
    }

    /**
     * Tests that the PUT API requires a payload. i.e non empty payloads give an error.
     *
     * @throws Exception
     */
    @Test
    public void testPayloadMandatory() throws Exception {
        setup();

        rh.sendAdminCertificate = true;
        response = rh.executePutRequest(ENDPOINT, "", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        JsonNode settings = DefaultObjectMapper.readTree(response.getBody());
        assertThat(settings.get("reason").asText(), is(RequestContentValidator.ValidationError.PAYLOAD_MANDATORY.message()));
    }

    /**
     * Tests 4 scenarios for accessing and using the API.
     * No creds, no admin certificate - UNAUTHORIZED
     * non admin creds, no admin certificate - FORBIDDEN
     * admin creds, no admin certificate - FORBIDDEN
     * any creds, admin certificate - OK
     *
     * @throws Exception
     */
    @Test
    public void testAllowlistApi() throws Exception {
        setupWithRestRoles();
        // No creds, no admin certificate - UNAUTHORIZED
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_UNAUTHORIZED, false);

        // non admin creds, no admin certificate - FORBIDDEN
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_FORBIDDEN, false, nonAdminCredsHeader);

        // admin creds, no admin certificate - FORBIDDEN
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_FORBIDDEN, false, adminCredsHeader);

        // any creds, admin certificate - OK
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_OK, true, nonAdminCredsHeader);
    }

    @Test
    public void testAllowlistApiWithPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());

        final Header restApiAdminHeader = encodeBasicHeader("rest_api_admin_user", "rest_api_admin_user");
        final Header restApiAllowlistHeader = encodeBasicHeader("rest_api_admin_allowlist", "rest_api_admin_allowlist");
        final Header restApiUserHeader = encodeBasicHeader("test", "test");

        checkGetAndPutAllowlistPermissions(HttpStatus.SC_FORBIDDEN, false, restApiUserHeader);
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_OK, false, restApiAdminHeader);
    }

    @Test
    public void testAllowlistApiWithAllowListPermissions() throws Exception {
        setupWithRestRoles(Settings.builder().put(SECURITY_RESTAPI_ADMIN_ENABLED, true).build());

        final Header restApiAllowlistHeader = encodeBasicHeader("rest_api_admin_allowlist", "rest_api_admin_allowlist");
        final Header restApiUserHeader = encodeBasicHeader("test", "test");

        checkGetAndPutAllowlistPermissions(HttpStatus.SC_FORBIDDEN, false, restApiUserHeader);
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_OK, false, restApiAllowlistHeader);
    }

    @Test
    public void testAllowlistAuditComplianceLogging() throws Exception {
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false)
            .put(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, true)
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .put(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, "authenticated,GRANTED_PRIVILEGES")
            .build();
        setupWithRestRoles(settings);
        TestAuditlogImpl.clear();

        // any creds, admin certificate - OK
        checkGetAndPutAllowlistPermissions(HttpStatus.SC_OK, true, nonAdminCredsHeader);

        // TESTS THAT 1 READ AND 1 WRITE HAPPENS IN testGetAndPut()
        final Map<AuditCategory, Long> expectedCategoryCounts = ImmutableMap.of(
            AuditCategory.COMPLIANCE_INTERNAL_CONFIG_READ,
            2L,
            AuditCategory.COMPLIANCE_INTERNAL_CONFIG_WRITE,
            1L
        );
        Map<AuditCategory, Long> actualCategoryCounts = TestAuditlogImpl.messages.stream()
            .collect(Collectors.groupingBy(AuditMessage::getCategory, Collectors.counting()));

        assertThat(actualCategoryCounts, equalTo(expectedCategoryCounts));
    }

    @Test
    public void testAllowlistInvalidHttpRequestMethod() throws Exception {
        setup();
        rh.sendAdminCertificate = true;

        response = rh.executePutRequest(
            ENDPOINT,
            "{\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GE\"],\"/_cat/indices\": [\"PUT\"] }}",
            adminCredsHeader
        );
        assertThat(response.getBody(), response.getStatusCode(), equalTo(HttpStatus.SC_INTERNAL_SERVER_ERROR));
        assertTrue(response.getBody().contains("\\\"GE\\\": not one of the values accepted for Enum class"));
    }

    /**
     * Tests that the PATCH Api works correctly.
     * Note: boolean variables are not recognized as valid paths in "replace" operation when they are false.
     * To get around this issue, to update boolean variables (here: 'enabled'), one must use the "add" operation instead.
     *
     * @throws Exception
     */
    @Test
    public void testPatchApi() throws Exception {
        setup();
        rh.sendAdminCertificate = true;

        // PATCH entire config entry
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"replace\", \"path\": \"/config\", \"value\": {\"enabled\": true, \"requests\": {\"/_cat/nodes\": [\"GET\"],\"/_cat/indices\": [\"PUT\"] }}}]",
            new Header[0]
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertThat(
            response.getBody(),
            is("{\"config\":{\"enabled\":true,\"requests\":{\"/_cat/nodes\":[\"GET\"],\"/_cat/indices\":[\"PUT\"]}}}")
        );

        // PATCH just requests
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"replace\", \"path\": \"/config/requests\", \"value\": {\"/_cat/nodes\": [\"GET\"]}}]",
            new Header[0]
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertTrue(response.getBody().contains("\"requests\":{\"/_cat/nodes\":[\"GET\"]}"));

        // PATCH just allowlisted_enabled using "replace" operation - works when enabled is already true
        response = rh.executePatchRequest(
            ENDPOINT,
            "[{ \"op\": \"replace\", \"path\": \"/config/enabled\", \"value\": false}]",
            new Header[0]
        );
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));

        // PATCH just enabled using "add" operation when it is currently false - works correctly
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": true}]", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":true"));

        // PATCH just enabled using "add" operation when it is currently true - works correctly
        response = rh.executePatchRequest(ENDPOINT, "[{ \"op\": \"add\", \"path\": \"/config/enabled\", \"value\": false}]", new Header[0]);
        assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        response = rh.executeGetRequest(ENDPOINT, adminCredsHeader);
        assertTrue(response.getBody().contains("\"enabled\":false"));
    }
}
