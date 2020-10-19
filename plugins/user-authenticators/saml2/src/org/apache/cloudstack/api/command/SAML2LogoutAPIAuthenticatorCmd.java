// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package org.apache.cloudstack.api.command;

import com.cloud.api.response.ApiResponseSerializer;
import com.cloud.user.Account;
import org.apache.cloudstack.api.APICommand;
import org.apache.cloudstack.api.ApiErrorCode;
import org.apache.cloudstack.api.ApiServerService;
import org.apache.cloudstack.api.BaseCmd;
import org.apache.cloudstack.api.ServerApiException;
import org.apache.cloudstack.api.auth.APIAuthenticationType;
import org.apache.cloudstack.api.auth.APIAuthenticator;
import org.apache.cloudstack.api.auth.PluggableAPIAuthenticator;
import org.apache.cloudstack.api.response.LogoutCmdResponse;
import org.apache.cloudstack.saml.SAML2AuthManager;
import org.apache.cloudstack.saml.SAMLPluginConstants;
import org.apache.cloudstack.saml.SAMLProviderMetadata;
import org.apache.cloudstack.saml.SAMLUtils;
import org.apache.cloudstack.saml.SAMLTokenVO;
import org.apache.log4j.Logger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.ConfigurationException;
// import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.xml.sax.SAXException;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.FactoryConfigurationError;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.net.InetAddress;

@APICommand(name = "samlSlo", description = "SAML Global Log Out API", responseObject = LogoutCmdResponse.class, entityType = {})
public class SAML2LogoutAPIAuthenticatorCmd extends BaseCmd implements APIAuthenticator {
    public static final Logger s_logger = Logger.getLogger(SAML2LogoutAPIAuthenticatorCmd.class.getName());
    private static final String s_name = "logoutresponse";

    @Inject
    ApiServerService _apiServer;

    SAML2AuthManager _samlAuthManager;

    /////////////////////////////////////////////////////
    /////////////// API Implementation///////////////////
    /////////////////////////////////////////////////////

    @Override
    public String getCommandName() {
        return s_name;
    }

    @Override
    public long getEntityOwnerId() {
        return Account.ACCOUNT_TYPE_NORMAL;
    }

    @Override
    public void execute() throws ServerApiException {
        // We should never reach here
        throw new ServerApiException(ApiErrorCode.METHOD_NOT_ALLOWED, "This is an authentication api, cannot be used directly");
    }

    public LogoutRequest processSAMLRequest(String requestMessage) {
        LogoutRequest requestObject = null;
        try {
            DefaultBootstrap.bootstrap();
            requestObject = SAMLUtils.decodeSAMLLogoutRequest(requestMessage);
        } catch (ConfigurationException | FactoryConfigurationError | ParserConfigurationException | SAXException | IOException | UnmarshallingException e) {
            s_logger.error("SAMLRequest processing error: " + e.getMessage());
        }
        return requestObject;
    }

    @Override
    public String authenticate(String command, Map<String, Object[]> params, HttpSession session, InetAddress remoteAddress, String responseType, StringBuilder auditTrailSb, final HttpServletRequest req, final HttpServletResponse resp) throws ServerApiException {
        auditTrailSb.append("=== SAML SLO Logging out ===");
        LogoutCmdResponse response = new LogoutCmdResponse();
        response.setDescription("success");
        response.setResponseName(getCommandName());
        String responseString = ApiResponseSerializer.toSerializedString(response, responseType);

        SAMLProviderMetadata spMetadata = _samlAuthManager.getSPMetadata();
        SAMLProviderMetadata idpMetadata = null;
        if (session != null) {
            String idpId = (String) session.getAttribute(SAMLPluginConstants.SAML_IDPID);
            idpMetadata = _samlAuthManager.getIdPMetadata(idpId);
        }
        if (SAML2AuthManager.SAMLIsIdentityProviderSloEnabled.value() && params != null && params.containsKey("SAMLRequest")) {
            final String samlRequest = ((String[])params.get(SAMLPluginConstants.SAML_REQUEST))[0];
            final LogoutRequest processedSAMLRequest = processSAMLRequest(samlRequest);
            s_logger.debug("SAML IdP initiated Slo");
            if (processedSAMLRequest != null) {
                String targetSessionIndex = null;
                final List<SessionIndex> sessionIndexes = processedSAMLRequest.getSessionIndexes();
                for (SessionIndex sessionIndex : sessionIndexes) {
                    if (sessionIndex.getSessionIndex() != null) {
                        targetSessionIndex = sessionIndex.getSessionIndex();
                        break;
                    }
                }
                final String samlSessionIndex = (session == null) ? null : (String) session.getAttribute(SAMLPluginConstants.SAML_SESSION_INDEX);
                final SAMLTokenVO token = (targetSessionIndex == null) ? null : _samlAuthManager.getTokenBySessionIndexAndNotSloUrl(targetSessionIndex, SAMLUtils.getCurrentUrl(req));
                s_logger.debug("Current URL: " + SAMLUtils.getCurrentUrl(req) + " stored URL is " + token.getSloUrl());
                s_logger.debug("SAML received Slo for Session Index " + targetSessionIndex + " user's current Session Index is " + samlSessionIndex);
                if (targetSessionIndex == null) {
                    s_logger.debug("SAML SessionIndex missing from Slo request, sending failure");
                    try {
                        resp.sendRedirect(SAMLUtils.buildLogoutResponseUrl(processedSAMLRequest.getID(), spMetadata, idpMetadata, StatusCode.REQUESTER_URI, "No session Index in LogoffRequeset", SAML2AuthManager.SAMLSignatureAlgorithm.value()));
                    } catch (IOException ignored) {
                        s_logger.error("[ignored] SAML IOException sending Slo failure to IdP.", ignored);
                    }
                } else if (targetSessionIndex.equals(samlSessionIndex)) {
                    s_logger.debug("SAML Idp initiated Slo successful, sending success");
                    try {
                        resp.sendRedirect(SAMLUtils.buildLogoutResponseUrl(processedSAMLRequest.getID(), spMetadata, idpMetadata, StatusCode.SUCCESS_URI, null, SAML2AuthManager.SAMLSignatureAlgorithm.value()));
                    } catch (IOException ignored) {
                        s_logger.error("[ignored] SAML IOException sending Slo success to Idp.", ignored);
                    }
                } else if (token != null && token.getSloUrl() != null) {
                    s_logger.debug("SAML redirecting Slo request to " + token.getSloUrl());
                    try {
                        resp.setStatus(HttpServletResponse.SC_TEMPORARY_REDIRECT);
                        resp.setHeader("Location",token.getSloUrl());
                        resp.flushBuffer();
                    } catch (IOException ignored) {
                         s_logger.error("[ignored] sending redirect to user's SAML Slo URL failed.", ignored);
                    }
                } else {
                    s_logger.debug("SAML Session Index in Idp initiated Slo not found, sending failure");
                    try {
                        resp.sendRedirect(SAMLUtils.buildLogoutResponseUrl(processedSAMLRequest.getID(), spMetadata, idpMetadata, StatusCode.REQUESTER_URI, "No session Index in LogoffRequeset", SAML2AuthManager.SAMLSignatureAlgorithm.value()));
                    } catch (IOException ignored) {
                        s_logger.error("[ignored] SAML IOException sending Slo failure to IdP.", ignored);
                    }
                }
                if (token != null) {
                    final int removedTokens = _samlAuthManager.removeTokensBySessionIndexAndSloUrl(targetSessionIndex, token.getSloUrl());
                    s_logger.debug("SAML removed " + removedTokens + " related to IdP Slo request");
                }
            } else {
                s_logger.error("SAML IdP initiated LogoutRequest was null");
            }

            return responseString;
        }

        if (session == null) {
            try {
                resp.sendRedirect(SAML2AuthManager.SAMLCloudStackRedirectionUrl.value());
            } catch (IOException ignored) {
                s_logger.info("[ignored] sending redirected failed.", ignored);
            }
            return responseString;
        }

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException | FactoryConfigurationError e) {
            s_logger.error("OpenSAML Bootstrapping error: " + e.getMessage());
            throw new ServerApiException(ApiErrorCode.ACCOUNT_ERROR, _apiServer.getSerializedApiError(ApiErrorCode.ACCOUNT_ERROR.getHttpCode(),
                    "OpenSAML Bootstrapping error while creating SP MetaData",
                    params, responseType));
        }

        if (params != null && params.containsKey("SAMLResponse")) {
            try {
                final String samlResponse = ((String[])params.get(SAMLPluginConstants.SAML_RESPONSE))[0];
                Response processedSAMLResponse = SAMLUtils.decodeSAMLResponse(samlResponse);
                String statusCode = processedSAMLResponse.getStatus().getStatusCode().getValue();
                if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
                    throw new ServerApiException(ApiErrorCode.INTERNAL_ERROR, _apiServer.getSerializedApiError(ApiErrorCode.INTERNAL_ERROR.getHttpCode(),
                            "SAML SLO LogoutResponse status is not Success",
                            params, responseType));
                }
            } catch (ConfigurationException | FactoryConfigurationError | ParserConfigurationException | SAXException | IOException | UnmarshallingException e) {
                s_logger.error("SAMLResponse processing error: " + e.getMessage());
            }
            try {
                resp.sendRedirect(SAML2AuthManager.SAMLCloudStackRedirectionUrl.value());
            } catch (IOException ignored) {
                s_logger.info("[ignored] second redirected sending failed.", ignored);
            }
            return responseString;
        }

        String idpId = (String) session.getAttribute(SAMLPluginConstants.SAML_IDPID);
        String nameId = (String) session.getAttribute(SAMLPluginConstants.SAML_NAMEID);
        if (idpMetadata == null || nameId == null || nameId.isEmpty()) {
            try {
                resp.sendRedirect(SAML2AuthManager.SAMLCloudStackRedirectionUrl.value());
            } catch (IOException ignored) {
                s_logger.info("[ignored] final redirected failed.", ignored);
            }
            return responseString;
        }

        try {
            String redirectUrl = SAMLUtils.buildLogoutRequestUrl(nameId, spMetadata, idpMetadata, SAML2AuthManager.SAMLSignatureAlgorithm.value());
            resp.sendRedirect(redirectUrl);
        } catch (IOException e) {
            s_logger.error("SAML SLO error: " + e.getMessage());
            throw new ServerApiException(ApiErrorCode.ACCOUNT_ERROR, _apiServer.getSerializedApiError(ApiErrorCode.ACCOUNT_ERROR.getHttpCode(),
                    "SAML Single Logout Error",
                    params, responseType));
        }
        return responseString;
    }

    @Override
    public APIAuthenticationType getAPIType() {
        return APIAuthenticationType.LOGOUT_API;
    }

    @Override
    public void setAuthenticators(List<PluggableAPIAuthenticator> authenticators) {
        for (PluggableAPIAuthenticator authManager: authenticators) {
            if (authManager != null && authManager instanceof SAML2AuthManager) {
                _samlAuthManager = (SAML2AuthManager) authManager;
            }
        }
        if (_samlAuthManager == null) {
            s_logger.error("No suitable Pluggable Authentication Manager found for SAML2 Login Cmd");
        }
    }
}
