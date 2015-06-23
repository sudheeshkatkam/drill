/**
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
package org.apache.drill.exec.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import org.apache.drill.common.AutoCloseables;
import org.apache.drill.exec.ZookeeperHelper;
import org.apache.drill.exec.exception.DrillbitStartupException;
import org.apache.drill.exec.proto.UserBitShared.QueryProfile;
import org.apache.drill.exec.server.rest.QueryWrapper.QueryResult;
import org.apache.drill.exec.server.rest.profile.ProfileResources.ProfileInfo;
import org.apache.drill.exec.server.rest.profile.ProfileResources.QueryProfiles;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;

import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestRestClient {
  private static final Logger logger = org.slf4j.LoggerFactory.getLogger(TestRestClient.class);

  private static final ObjectMapper mapper = new ObjectMapper();
  private static final int OK_STATUS = ClientResponse.Status.OK.getStatusCode();

  private static ZookeeperHelper zkHelper;
  private static RemoteServiceSet remoteServiceSet;
  private static Drillbit drillbit;
  private static String baseUrl;

  @BeforeClass
  public static void startDrillbit() throws Exception {
    zkHelper = new ZookeeperHelper();
    zkHelper.startZookeeper(1);

    // use a non-null service set so that the drillbits can use port hunting
    remoteServiceSet = RemoteServiceSet.getLocalServiceSet();

    try {
      drillbit = Drillbit.start(zkHelper.getConfig(), remoteServiceSet);
      baseUrl = "http://" + drillbit.getContext().getEndpoint().getAddress() + ":8047";
    } catch (final DrillbitStartupException e) {
      throw new RuntimeException("Failed to start Drillbit.", e);
    }
  }

  @AfterClass
  public static void stopDrillbit() {
    if (drillbit == null) {
      throw new IllegalStateException("No Drillbit found.");
    }

    try {
      drillbit.close();
    } catch (final Exception e) {
      final String message = "Error shutting down Drillbit.";
      System.err.println(message);
      logger.warn(message, e);
    }

    if (remoteServiceSet != null) {
      AutoCloseables.close(remoteServiceSet, logger);
      remoteServiceSet = null;
    }
    zkHelper.stopZookeeper();
  }

  @Test
  public void postQueryJson() {
    final String postQueryUrl = baseUrl + "/query.json";
    final String payload = "{\"queryType\" : \"SQL\", \"query\" : \"SELECT * FROM cp.`employee.json` LIMIT 2\"}";

    final WebResource resource = Client.create().resource(postQueryUrl);
    final ClientResponse response = resource
      .accept(MediaType.APPLICATION_JSON)
      .type(MediaType.APPLICATION_JSON)
      .entity(payload)
      .post(ClientResponse.class);

    final String result = response.getEntity(String.class);
    final int status = response.getStatus();
    response.close();
    assertTrue(status == OK_STATUS);

    final QueryResult queryResult;
    try {
      queryResult = mapper.readValue(result, QueryResult.class);
    } catch (final IOException e) {
      fail();
      return; // does not happen
    }

    final int columns = queryResult.columns.size();
    assertTrue(columns > 0);
    assertEquals(2, queryResult.rows.size());
    assertEquals(columns, queryResult.rows.get(0).size());
    assertEquals(columns, queryResult.rows.get(1).size());
  }

  // this method gets all profiles and returns the query id of the first profile
  private String getFirstProfileQueryId() {
    final String profilesUrl = baseUrl + "/profiles.json";

    final WebResource resource = Client.create().resource(profilesUrl);
    final ClientResponse response = resource.get(ClientResponse.class);

    final String result = response.getEntity(String.class);
    final int status = response.getStatus();
    response.close();
    assertTrue(status == OK_STATUS);

    final QueryProfiles profiles;
    try {
      profiles = mapper.readValue(result, QueryProfiles.class);
    } catch (final IOException e) {
      fail("Mapper could not deserialize the result: " + e);
      return "does not happen.";
    }

    final List<ProfileInfo> completedQueries = profiles.getCompletedQueries();
    if (completedQueries.size() == 0) { // ensure there is at least one completed query
      postQueryJson();
      return getFirstProfileQueryId();
    }

    return profiles.getCompletedQueries().get(0).getQueryId();
  }

  @Test
  public void getProfilesJson() {
    getFirstProfileQueryId();
  }

  @Test
  public void getProfileJson() {
    final String firstId = getFirstProfileQueryId();
    final String profileUrl = baseUrl + "/profiles/" + firstId + ".json";

    final WebResource resource = Client.create().resource(profileUrl);
    final ClientResponse response = resource.get(ClientResponse.class);

    final String result = response.getEntity(String.class);
    final int status = response.getStatus();
    response.close();
    assertTrue(status == OK_STATUS);

    final QueryProfile profile;
    try {
      profile = mapper.readValue(result, QueryProfile.class);
    } catch (final IOException e) {
      fail("Mapper could not deserialize the result: " + e);
      return; // does not happen
    }
    profile.toString();
  }
}
