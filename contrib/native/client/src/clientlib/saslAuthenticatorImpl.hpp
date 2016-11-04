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

#ifndef DRILLCLIENT_SASLAUTHENTICATORIMPL_HPP
#define DRILLCLIENT_SASLAUTHENTICATORIMPL_HPP

#include <string>
#include <map>
#include <vector>

#include "drill/drillClient.hpp"

#include "sasl/sasl.h"
#include "sasl/saslplug.h"

namespace Drill {

class SaslAuthenticatorImpl {

public:

    static const std::map<std::string, std::string> MECHANISM_MAPPING;

    SaslAuthenticatorImpl(const DrillUserProperties *const properties);

    ~SaslAuthenticatorImpl();

    int init(const std::vector<std::string> mechanisms, std::string &chosenMech,
             const char **out, unsigned *outlen);

    int step(const char *const in, const unsigned inlen, const char **out, unsigned *outlen) const;

    static int passwordCallback(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret);

    static int userNameCallback(void *context, int id, const char **result, unsigned int *len);

private:

    static boost::mutex s_mutex;
    static bool s_initialized;

    const DrillUserProperties *const m_properties;
    sasl_conn_t *m_pConnection;
    std::string m_username;
    std::string m_password;
    sasl_secret_t *m_secret;

};

} /* namespace Drill */

#endif //DRILLCLIENT_SASLAUTHENTICATORIMPL_HPP
