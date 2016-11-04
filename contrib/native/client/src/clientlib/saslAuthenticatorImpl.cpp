/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>
#include <boost/algorithm/string.hpp>
#include <boost/assign.hpp>
#include "saslAuthenticatorImpl.hpp"

#include "drillClientImpl.hpp"
#include "logger.hpp"

namespace Drill {

#define DEFAULT_SERVICE_NAME "drill"

#define KERBEROS_SIMPLE_NAME "kerberos"
#define KERBEROS_SASL_NAME "gssapi"
#define PLAIN_NAME "plain"

const std::map<std::string, std::string> SaslAuthenticatorImpl::MECHANISM_MAPPING = boost::assign::map_list_of
    (KERBEROS_SIMPLE_NAME, KERBEROS_SASL_NAME)
    (PLAIN_NAME, PLAIN_NAME)
;

boost::mutex SaslAuthenticatorImpl::s_mutex;
bool SaslAuthenticatorImpl::s_initialized = false;

typedef int (*sasl_callback_proc_t)(void); // see sasl_callback_ft

int SaslAuthenticatorImpl::userNameCallback(void *context, int id, const char **result, unsigned *len) {
    const std::string* const username = (const std::string* const) context;

    if ((SASL_CB_USER == id || SASL_CB_AUTHNAME == id)
        && username != NULL) {
        *result = username->c_str();
        // *len = (unsigned int) username->length();
    }
    return SASL_OK;
}

int SaslAuthenticatorImpl::passwordCallback(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret) {
    const SaslAuthenticatorImpl* const authenticator = (const SaslAuthenticatorImpl* const) context;

    if (SASL_CB_PASS == id) {
        const std::string password = authenticator->m_password;
        const size_t length = password.length();
        authenticator->m_secret->len = length;
        std::memcpy(authenticator->m_secret->data, password.c_str(), length);
        *psecret = authenticator->m_secret;
    }
   return SASL_OK;
}

SaslAuthenticatorImpl::SaslAuthenticatorImpl(const DrillUserProperties* const properties) :
    m_properties(properties), m_pConnection(NULL), m_secret(NULL) {

    if (!s_initialized) {
        boost::lock_guard<boost::mutex> guard(SaslAuthenticatorImpl::s_mutex);
        if (!s_initialized) {
            s_initialized = true;

            // set plugin path if provided
            if (DrillClientConfig::getSaslPluginPath()) {
                char *saslPluginPath = const_cast<char *>(DrillClientConfig::getSaslPluginPath());
                sasl_set_path(0, saslPluginPath);
            }

            sasl_client_init(NULL);
            { // for debugging purposes
                const char **mechanisms = sasl_global_listmech();
                int i = 1;
                DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "SASL mechanisms available on client: " << std::endl;)
                while (mechanisms[i] != NULL) {
                    DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << i << " : " << mechanisms[i] << std::endl;)
                    i++;
                }
            }
        }
    }
}

SaslAuthenticatorImpl::~SaslAuthenticatorImpl() {
    if (m_secret) {
        free(m_secret);
    }
    // may be used to negotiated security layers before disposing in the future
    if (m_pConnection) {
        sasl_dispose(&m_pConnection);
    }
    m_pConnection = NULL;
}

int SaslAuthenticatorImpl::init(const std::vector<std::string> mechanisms,
                                std::string &chosenMech,
                                const char **out,
                                unsigned *outlen) {
    // find and set parameters
    std::string authMechanismToUse;
    std::string serviceName;
    std::string serviceHost;
    for (size_t i = 0; i < m_properties->size(); i++) {
        const std::string key = m_properties->keyAt(i);
        const std::string value = m_properties->valueAt(i);

        if (key == USERPROP_SERVICE_HOST) {
            DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Setting service host" << std::endl;)
            serviceHost = value;
        } else if (key == USERPROP_SERVICE_NAME) {
            DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Setting service name" << std::endl;)
            serviceName = value;
        } else if (key == USERPROP_PASSWORD) {
            DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Setting password" << std::endl;)
            m_password = value;
            m_secret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t) + m_password.length());
            authMechanismToUse = "plain";
        } else if (key == USERPROP_USERNAME) {
            DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Setting name" << std::endl;)
            m_username = value;
        } else if (key == USERPROP_AUTH_MECHANISM) {
            DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Setting auth mechanism" << std::endl;)
            authMechanismToUse = value;
        }
    }
    if (authMechanismToUse.empty()) {
        return SASL_NOMECH;
    }

    // check if requested mechanism is supported by server
    boost::algorithm::to_lower(authMechanismToUse);
    bool isSupportedByServer = false;
    for (size_t i = 0; i < mechanisms.size(); i++) {
        std::string mechanism = mechanisms[i];
        boost::algorithm::to_lower(mechanism);
        if (authMechanismToUse == mechanism) {
            isSupportedByServer = true;
        }
    }
    if (!isSupportedByServer) {
        return SASL_NOMECH;
    }

    // find the SASL name
    const std::map<std::string, std::string>::const_iterator it =
            SaslAuthenticatorImpl::MECHANISM_MAPPING.find(authMechanismToUse);
    std::string saslMechanismToUse;
    if (it == SaslAuthenticatorImpl::MECHANISM_MAPPING.end()) {
        return SASL_NOMECH;
    } else {
        saslMechanismToUse = it->second;
        DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Requested SASL mechanism to use: " << saslMechanismToUse << std::endl;)
    }

    // setup callbacks and parameters
    const sasl_callback_t callbacks[] = {
        {
            SASL_CB_USER, (sasl_callback_proc_t) &userNameCallback, (void *) &m_username
        }, {
            SASL_CB_AUTHNAME, (sasl_callback_proc_t) &userNameCallback, (void *) &m_username
        }, {
            SASL_CB_PASS, (sasl_callback_proc_t) &passwordCallback, (void *) this
        }, {
            SASL_CB_LIST_END, NULL, NULL
        }
    };
    if (serviceName.empty()) {
        serviceName = DEFAULT_SERVICE_NAME;
    }

    // create SASL client
    int saslResult = sasl_client_new(serviceName.c_str(), serviceHost.c_str(), NULL /** iplocalport */,
                                     NULL /** ipremoteport */, callbacks, 0 /** sec flags */, &m_pConnection);
    if (saslResult == SASL_OK) {
        DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Initialized SASL client successfully. " << std::endl;)
    } else {
        DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Initialized SASL client failed. Code: " << saslResult << std::endl;)
        return saslResult;
    }

    // initiate; for now pass in only one mechanism
    const char *mech;
    saslResult = sasl_client_start(m_pConnection, saslMechanismToUse.c_str(), NULL /** no prompt */,
                                   out, outlen, &mech);
    if (saslResult == SASL_OK) {
        chosenMech = authMechanismToUse;
        DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Chosen SASL mechanism: " << mech << std::endl;)
    } else {
        DRILL_MT_LOG(DRILL_LOG(LOG_TRACE) << "Failed to choose a mechanism. Code: " << saslResult << std::endl;)
    }
    return saslResult;
}

int SaslAuthenticatorImpl::step(const char* const in,
                                const unsigned inlen,
                                const char **out,
                                unsigned *outlen) const {
    return sasl_client_step(m_pConnection, in, inlen, NULL /** no prompt */, out, outlen);
}

} /* namespace Drill */
