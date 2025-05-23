/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.opensearch.security.ssl.rest;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.ssl.SslConfiguration;
import org.opensearch.security.ssl.SslSettingsManager;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.ssl.config.SslParameters;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLRequestHelper;
import org.opensearch.security.ssl.util.SSLRequestHelper.SSLInfo;
import org.opensearch.transport.client.node.NodeClient;

public class SecuritySSLInfoAction extends BaseRestHandler {
    private static final List<Route> routes = Collections.singletonList(new Route(Method.GET, "/_opendistro/_security/sslinfo"));

    private final Logger log = LogManager.getLogger(this.getClass());
    private final SslSettingsManager sslSettingsManager;
    final PrincipalExtractor principalExtractor;
    private final Path configPath;
    private final Settings settings;

    public SecuritySSLInfoAction(
        final Settings settings,
        final Path configPath,
        final SslSettingsManager sslSettingsManager,
        final PrincipalExtractor principalExtractor
    ) {
        super();
        this.settings = settings;
        this.sslSettingsManager = sslSettingsManager;
        this.principalExtractor = principalExtractor;
        this.configPath = configPath;
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            final Boolean showDn = request.paramAsBoolean("show_dn", Boolean.FALSE);

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
                    SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(
                        settings,
                        configPath,
                        SecurityRequestFactory.from(request),
                        principalExtractor
                    );
                    X509Certificate[] certs = sslInfo == null ? null : sslInfo.getX509Certs();
                    X509Certificate[] localCerts = sslInfo == null ? null : sslInfo.getLocalCertificates();

                    builder.startObject();

                    builder.field("principal", sslInfo == null ? null : sslInfo.getPrincipal());
                    builder.field("peer_certificates", certs != null && certs.length > 0 ? certs.length + "" : "0");

                    if (showDn == Boolean.TRUE) {
                        builder.field(
                            "peer_certificates_list",
                            certs == null
                                ? null
                                : Arrays.stream(certs).map(c -> c.getSubjectX500Principal().getName()).collect(Collectors.toList())
                        );
                        builder.field(
                            "local_certificates_list",
                            localCerts == null
                                ? null
                                : Arrays.stream(localCerts).map(c -> c.getSubjectX500Principal().getName()).collect(Collectors.toList())
                        );
                    }

                    builder.field("ssl_protocol", sslInfo == null ? null : sslInfo.getProtocol());
                    builder.field("ssl_cipher", sslInfo == null ? null : sslInfo.getCipher());
                    builder.field(
                        "ssl_provider_http",
                        sslSettingsManager.sslConfiguration(CertType.HTTP)
                            .map(SslConfiguration::sslParameters)
                            .map(SslParameters::provider)
                            .orElse(null)
                    );
                    builder.field(
                        "ssl_provider_transport_server",
                        sslSettingsManager.sslConfiguration(CertType.TRANSPORT)
                            .map(SslConfiguration::sslParameters)
                            .map(SslParameters::provider)
                            .orElse(null)
                    );
                    builder.field(
                        "ssl_provider_transport_client",
                        sslSettingsManager.sslConfiguration(CertType.TRANSPORT_CLIENT)
                            .map(SslConfiguration::sslParameters)
                            .map(SslParameters::provider)
                            .orElse(null)
                    );
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    log.error("Error handle request ", e1);
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if (builder != null) {
                        builder.close();
                    }
                }

                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "OpenSearch Security SSL Info";
    }
}
