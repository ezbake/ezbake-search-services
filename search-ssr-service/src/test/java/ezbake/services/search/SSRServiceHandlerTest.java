/*   Copyright (C) 2013-2014 Computer Sciences Corporation
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
 * limitations under the License. */

package ezbake.services.search;

import java.io.File;
import java.net.URL;
import java.util.*;

import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ezbake.base.thrift.*;
import ezbake.base.thrift.Date;
import ezbake.configuration.ClasspathConfigurationLoader;
import ezbake.configuration.EzConfiguration;
import ezbake.configuration.constants.EzBakePropertyConstants;
import ezbake.data.common.TimeUtil;
import ezbake.data.elastic.EzElasticHandler;
import ezbake.data.elastic.thrift.*;
import ezbake.ezdiscovery.ServiceDiscoveryClient;
import ezbake.security.impl.ua.FileUAService;
import ezbake.security.service.processor.EzSecurityHandler;
import ezbake.security.thrift.ezsecurityConstants;
import ezbake.security.ua.UAModule;
import ezbake.services.centralPurge.thrift.ezCentralPurgeServiceConstants;
import ezbake.services.search.utils.SSRUtils;
import ezbake.thrift.ThriftServerPool;
import ezbake.thrift.ThriftTestUtils;
import ezbakehelpers.ezconfigurationhelpers.elasticsearch.ElasticsearchConfigurationHelper;

import org.apache.thrift.TException;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeBuilder;
import org.junit.*;

import static org.junit.Assert.*;

import com.google.common.base.Charsets;
import com.google.common.collect.Maps;
import com.google.common.io.Resources;

public class SSRServiceHandlerTest {
    private static SSRServiceHandler ssrService;
    private static ThriftServerPool serverPool;
    private static EzSecurityToken securityToken;
    private static final String SERVICE_NAME = "documentDataset";
    private static Node node;
    private static Properties props;

    @BeforeClass
    public static void startUp() {
        try {
            props = new EzConfiguration(new ClasspathConfigurationLoader()).getProperties();
            ElasticsearchConfigurationHelper elasticConfig = new ElasticsearchConfigurationHelper(props);
            final Settings settings =
                    ImmutableSettings.settingsBuilder()
                            .put("script.disable_dynamic", false)
                            .put("cluster.name", elasticConfig.getElasticsearchClusterName())
                                    // Use supplied cluster because production would use it
                            .put("network.host", elasticConfig.getElasticsearchHost())
                                    // Use supplied host because production would use it
                            .put("transport.tcp.port", elasticConfig.getElasticsearchPort())
                                    // Use supplied port because production would use it
                            .put("script.native.visibility.type",
                                    "ezbake.data.elastic.security.EzSecurityScriptFactory").build();

            node = NodeBuilder.nodeBuilder().local(false).settings(settings).node();
            node.start();
            Thread.sleep(3000);

            props = new EzConfiguration(new ClasspathConfigurationLoader()).getProperties();

            String securityId = props.getProperty(EzBakePropertyConstants.EZBAKE_SECURITY_ID);
            securityToken = ThriftTestUtils.generateTestSecurityToken(
                    securityId, securityId, Arrays.asList("U"));

            props.setProperty(EzBakePropertyConstants.EZBAKE_SSL_CIPHERS_KEY, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA");
            props.setProperty(UAModule.UA_SERVICE_IMPL, FileUAService.class.getCanonicalName());
            Properties securityConfig = new Properties();
            securityConfig.putAll(props);
            securityConfig.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY, System.getProperty("user.dir") + File.separator + "src/test/resources/pki/server");
            serverPool = new ThriftServerPool(securityConfig, 14000);
            serverPool.startCommonService(new EzSecurityHandler(), ezsecurityConstants.SERVICE_NAME, "12345");

            // Get the application name for the ezelastic service
            String ezelasticAppName = props.getProperty(SSRServiceHandler.EZELASTIC_APPLICATION_NAME_KEY, null);
            serverPool.startApplicationService(new EzElasticHandler(), SERVICE_NAME, ezelasticAppName, securityId);

            ServiceDiscoveryClient discovery = new ServiceDiscoveryClient(props);
            discovery.setSecurityIdForCommonService(ezCentralPurgeServiceConstants.SERVICE_NAME, securityId);
            discovery.close();

            ssrService = new SSRServiceHandler();
            props.setProperty(EzBakePropertyConstants.EZBAKE_CERTIFICATES_DIRECTORY, System.getProperty("user.dir") + File.separator + "src/test/resources/pki/client");
            ssrService.setConfigurationProperties(props);
            ssrService.getThriftProcessor();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @AfterClass
    public static void shutdown() throws Exception {
        node.client().admin().indices().prepareDelete("ssrindexing").get();
        node.stop();
        node.close();
        ssrService.shutdown();
        serverPool.shutdown();
    }

    @After
    public void cleanup() {
        node.client().prepareDeleteByQuery("ssrindexing")
                .setQuery(QueryBuilders.matchAllQuery())
                .execute()
                .actionGet();
    }

    @Test
    public void testGetTypeFromURI() {
        String type = ssrService.getTypeFromUri("SOCIAL://test/tag:search.twitter.com,2005:449728248529043456");
        assertEquals("Correct type generated", "SOCIAL:test", type);
    }

    @Test
    public void testSearchSsrCheckFormalVisibility() throws Exception {

        String uri = "DEV://test/tag:search.twitter.com,2005:475858716546592768";
        String formalVisibility = "U";
        String key = "testkey";
        String value = String.valueOf(new java.util.Date().getTime());

        String securityId = props.getProperty(EzBakePropertyConstants.EZBAKE_SECURITY_ID);
        EzSecurityToken token = ThriftTestUtils.generateTestSecurityToken(
                securityId, securityId, Arrays.asList(formalVisibility));

        List<IndexResponse> responses = populateTestData(uri, formalVisibility, null, key, value, token);
        assertEquals("One index response expected", 1, responses.size());
        assertTrue("Index response should be a success", responses.get(0).isSuccess());

        String search = QueryBuilders.matchQuery(key, value).toString();
        Query query = new Query().setSearchString(search).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SSRSearchResult results = ssrService.searchSSR(query, token);

        List<SSR> matchingSsrs = results.getMatchingRecords();
        assertEquals("Expect one matching record.", 1, matchingSsrs.size());

        SSR querySsr = matchingSsrs.get(0);

        assertNotNull("Visibility should not be null", querySsr.getVisibility());
        assertEquals("Formal Markings not equal", formalVisibility, querySsr.getVisibility().getFormalVisibility());
    }

    @Test
    public void testSearchSsrCheckExternalCommunityVisibility() throws Exception {

        String uri = "DEV://test/tag:search.twitter.com,2005:475858716546592768";
        String formalVisibility = "U";
        String extCommVisibility = "TEST";
        String key = "testkey";
        String value = String.valueOf(new java.util.Date().getTime());

        String securityId = props.getProperty(EzBakePropertyConstants.EZBAKE_SECURITY_ID);
        EzSecurityToken token = ThriftTestUtils.generateTestSecurityToken(
                securityId, securityId, Arrays.asList(formalVisibility));
        TreeSet<String> extCommSet = new TreeSet<>();
        extCommSet.add(extCommVisibility);
        token.getAuthorizations().setExternalCommunityAuthorizations(extCommSet);

        List<IndexResponse> responses = populateTestData(uri, formalVisibility, extCommVisibility, key, value, token);

        assertEquals("One index response expected", 1, responses.size());
        assertTrue("Index response should be a success", responses.get(0).isSuccess());

        //String search = QueryBuilders.queryString(value).toString();
        String search = QueryBuilders.matchQuery(key, value).toString();
        Query query = new Query().setSearchString(search).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SSRSearchResult results = ssrService.searchSSR(query, token);

        List<SSR> matchingSsrs = results.getMatchingRecords();
        assertEquals("Expect one matching record.", 1, matchingSsrs.size());

        SSR querySsr = matchingSsrs.get(0);

        assertNotNull("Visibility should not be null", querySsr.getVisibility());
        assertNotNull("Advanced Markings should not be null", querySsr.getVisibility().getAdvancedMarkings());
        assertEquals("External Community Visibility not equal", extCommVisibility,
                querySsr.getVisibility().getAdvancedMarkings().getExternalCommunityVisibility());
    }

    @Test
    public void testGetEnterpriseMetadata() throws Exception {
        populateTestData();

        // verify query by metadata
        String someCode22Query = QueryBuilders.multiMatchQuery("22", "some_code").toString();
        Query query = new Query().setSearchString(someCode22Query).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SSRSearchResult results = ssrService.searchSSR(query, securityToken);
        assertEquals("Should have one with some_code=22", 1, results.getTotalHits());

        String someCode14Query = QueryBuilders.multiMatchQuery("14", "some_code").toString();
        query = new Query().setSearchString(someCode14Query).setPage(new Page().setPageSize((short) 5).setOffset(0));
        results = ssrService.searchSSR(query, securityToken);
        assertEquals("Should have one with some_code=14", 1, results.getTotalHits());

        String someCodeNonExistentQuery = QueryBuilders.multiMatchQuery("6", "some_code").toString();
        query = new Query().setSearchString(someCodeNonExistentQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        results = ssrService.searchSSR(query, securityToken);
        assertEquals("Should have no match for some_code=6", 0, results.getTotalHits());

        String testProperty1TrueQuery = QueryBuilders.multiMatchQuery("true", "testProperty1").toString();
        query = new Query().setSearchString(testProperty1TrueQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        results = ssrService.searchSSR(query, securityToken);
        assertEquals("Should have 2 with testProperty1=true", 2, results.getTotalHits());

        String testProperty1FalseQuery = QueryBuilders.multiMatchQuery("false", "testProperty1").toString();
        query = new Query().setSearchString(testProperty1FalseQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        results = ssrService.searchSSR(query, securityToken);
        assertEquals("Should have no match for testProperty1=false", 0, results.getTotalHits());
    }

    @Test
    public void testBulkPut() throws TException {
        String key = "theField";
        String value1 = "first value";
        String value2 = "second value";

        Map<SSR, String> docs = Maps.newHashMap();
        SSR ssr1 = new SSR();
        ssr1.setUri("DEV://test/12345");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");
        String json = "{\"" + key + "\": \"" + value1 + "\"}";
        docs.put(ssr1, json);

        SSR ssr2 = new SSR();
        ssr2.setUri("DEV://test/123456789");
        ssr2.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr2.setSnippet("some_snippet");
        ssr2.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 2005)));
        ssr2.setTitle("ssr_title");
        json = "{\"" + key + "\": \"" + value2 + "\"}";
        docs.put(ssr2, json);

        List<IndexResponse> responses = ssrService.putWithDocs(docs, securityToken);
        assertEquals("One index response expected", 2, responses.size());
        assertTrue("Index response 0 should be a success", responses.get(0).isSuccess());
        assertTrue("Index response 1 should be a success", responses.get(1).isSuccess());

        // Query by SSR result date
        String devTestQuery = QueryBuilders.rangeQuery(SSRUtils.SSR_DATE_FIELD).lt("010000Z NOV 05").toString();
        Query query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SSRSearchResult result = ssrService.searchSSR(query, securityToken);
        assertEquals("Two matches returned for date query", 2, result.getTotalHits());

        // Query by free text
        devTestQuery = QueryBuilders.queryString(key + ":second").toString();
        query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        result = ssrService.searchSSR(query, securityToken);
        assertEquals("One match returned for free text query", 1, result.getTotalHits());
        assertEquals("Correct URI returned with SSR", ssr2.getUri(), result.getMatchingRecords().get(0).getUri());

        // Match query
        devTestQuery = QueryBuilders.matchQuery(key, "first").toString();
        query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        result = ssrService.searchSSR(query, securityToken);
        assertEquals("One match returned for free text query", 1, result.getTotalHits());
        assertEquals("Correct URI returned with SSR", ssr1.getUri(), result.getMatchingRecords().get(0).getUri());
    }

    @Test
    public void testHighlighting() throws TException {
        String key = "theField";
        String value1 = "lorem ipsum something or other";

        Map<SSR, String> docs = Maps.newHashMap();
        SSR ssr1 = new SSR();
        ssr1.setUri("DEV://test/12345");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");
        String json = "{\"" + key + "\": \"" + value1 + "\"}";
        docs.put(ssr1, json);

        List<IndexResponse> responses = ssrService.putWithDocs(docs, securityToken);
        assertEquals("One index response expected", 1, responses.size());
        assertTrue("Index response should be a success", responses.get(0).isSuccess());

        // Match query
        String devTestQuery = QueryBuilders.queryString("ipsum").toString();
        Query query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        query.setHighlighting(new HighlightRequest().setFields(Sets.newHashSet(new HighlightedField("*"))));
        SSRSearchResult result = ssrService.searchSSR(query, securityToken);
        assertEquals("One match returned for free text query", 1, result.getTotalHits());
        assertEquals("Correct URI returned with SSR", ssr1.getUri(), result.getMatchingRecords().get(0).getUri());
        assertTrue("Highlight returned with em tags", result.getHighlights().get(ssr1.getUri()).getResults().get(key).get(0).contains("<em>ipsum</em>"));
    }

    @Test
    public void testPassThroughSearch() throws TException {
        String key = "theField";
        String value1 = "lorem ipsum something or other";

        Map<SSR, String> docs = Maps.newHashMap();
        SSR ssr1 = new SSR();
        ssr1.setUri("DEV://test/12345");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");
        String json = "{\"" + key + "\": \"" + value1 + "\"}";
        docs.put(ssr1, json);

        List<IndexResponse> responses = ssrService.putWithDocs(docs, securityToken);
        assertEquals("One index response expected", 1, responses.size());
        assertTrue("Index response should be a success", responses.get(0).isSuccess());

        // Match query
        String devTestQuery = QueryBuilders.queryString("ipsum").toString();
        Query query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        query.setReturnedFields(Sets.newHashSet(key));
        SearchResult result = ssrService.search(query, securityToken);
        assertEquals("One match returned for free text query", 1, result.getTotalHits());
        assertEquals("Correct ID returned with JSON object", ssr1.getUri(), result.getMatchingDocuments().get(0).get_id());

        // Check that the requested field was returned
        JsonElement jsonElement = new JsonParser().parse(result.getMatchingDocuments().get(0).get_jsonObject());
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        assertTrue("Returned object contains the requested field", jsonObject.has(key));
        assertEquals("Correct value returned for field", value1, jsonObject.get(key).getAsString());
    }

    @Test
    public void testInsertMalformedObject() throws TException {
        SSR ssr1 = new SSR();
        ssr1.setUri("DEV://test/12345");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");
        String json = "{\"somedate\": \"2001/01/01\"}";

        Map<SSR, String> docs = Maps.newHashMap();
        docs.put(ssr1, json);
        ssrService.putWithDocs(docs, securityToken);

        ssr1 = new SSR();
        ssr1.setUri("DEV://test/123456789");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");
        json = "{\"somedate\": \"this is not a date\"}";

        docs = Maps.newHashMap();
        docs.put(ssr1, json);
        List<IndexResponse> responses = ssrService.putWithDocs(docs, securityToken);
        assertEquals("One index response expected", 1, responses.size());
        assertTrue("Index response should be a success", responses.get(0).isSuccess());

        // Make sure that the first document is in there
        String devTestQuery = QueryBuilders.rangeQuery("somedate").lt("2001/01/02").toString();
        Query query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SSRSearchResult result = ssrService.searchSSR(query, securityToken);
        assertEquals("One match returned for correct JSON", 1, result.getTotalHits());
        assertEquals("Result has the correct URI", "DEV://test/12345", result.getMatchingRecords().get(0).getUri());

        // Verify that the malformed document is searchable
        devTestQuery = QueryBuilders.queryString("this is not a date").toString();
        query = new Query().setSearchString(devTestQuery).setPage(new Page().setPageSize((short) 5).setOffset(0));
        result = ssrService.searchSSR(query, securityToken);
        assertEquals("One match returned for malformed JSON", 1, result.getTotalHits());
        assertEquals("Result has the correct URI", "DEV://test/123456789", result.getMatchingRecords().get(0).getUri());
    }

    private void populateTestData() throws Exception {
        HashMap<SSR, String> ssrJsonMap = Maps.newHashMap();
        URL url1 = Resources.getResource("source1.json");
        String source1 = Resources.toString(url1, Charsets.UTF_8);
        URL url2 = Resources.getResource("source2.json");
        String source2 = Resources.toString(url2, Charsets.UTF_8);

        SSR ssr1 = new SSR();
        ssr1.setUri("DEV://test/tag:search.twitter.com,2005:475858716546592768");
        ssr1.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr1.setSnippet("some_snippet");
        ssr1.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr1.setTitle("ssr_title");

        EnterpriseMetaData metaData = new EnterpriseMetaData();
        Map<String, String> tags = new HashMap<>();
        tags.put("testProperty1", "true");
        tags.put("some_code", "22");
        metaData.setTags(tags);
        ssr1.setMetaData(metaData);

        ssrJsonMap.put(ssr1, source1);

        SSR ssr2 = new SSR();
        ssr2.setUri("DEV://test/tag:search.twitter.com,2005:475858716546596474");
        ssr2.setVisibility(new Visibility().setFormalVisibility("U"));
        ssr2.setSnippet("some_snippet");
        ssr2.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr2.setTitle("ssr_title");

        EnterpriseMetaData metaData2 = new EnterpriseMetaData();
        Map<String, String> tags2 = new HashMap<>();
        tags2.put("testProperty1", "true");
        tags2.put("some_code", "14");
        metaData2.setTags(tags2);
        ssr2.setMetaData(metaData2);

        ssrJsonMap.put(ssr2, source2);

        ssrService.putWithDocs(ssrJsonMap, securityToken);

        Thread.sleep(1000);
    }

    private List<IndexResponse> populateTestData(String uri, String formalVisibility,
                                                 String extCommVisibility, String key, String value, EzSecurityToken token) throws Exception {

        HashMap<SSR, String> ssrJsonMap = Maps.newHashMap();
        String json = "{\"" + key + "\": \"" + value + "\"}";

        Visibility visibility = new Visibility();
        visibility.setFormalVisibility(formalVisibility);
        if (extCommVisibility != null) {
            visibility.setAdvancedMarkings(new AdvancedMarkings().setExternalCommunityVisibility(extCommVisibility));
        }

        SSR ssr = new SSR();
        ssr.setUri(uri);
        ssr.setVisibility(visibility);
        ssr.setSnippet("some_snippet");
        ssr.setResultDate(new DateTime(new Date((short) 10, (short) 5, (short) 1999)));
        ssr.setTitle("ssr_title");

        EnterpriseMetaData metaData = new EnterpriseMetaData();
        Map<String, String> tags = new HashMap<>();
        tags.put("testProperty1", "true");
        tags.put("some_code", "22");
        metaData.setTags(tags);
        ssr.setMetaData(metaData);

        ssrJsonMap.put(ssr, json);
        return ssrService.putWithDocs(ssrJsonMap, token);
    }

    @Test
    public void testPurgeStatus() throws TException {

        long purgeId1 = System.currentTimeMillis();
        PurgeState state1 = new PurgeState();
        state1.setPurgeId(purgeId1);
        state1.setPurgeStatus(PurgeStatus.PURGING);
        state1.setTimeStamp(TimeUtil.convertToThriftDateTime(System
                .currentTimeMillis()));
        state1.setPurged(Sets.<Long>newHashSet());
        state1.setNotPurged(Sets.<Long>newHashSet());
        state1.setSuggestedPollPeriod(10000);

        long purgeId2 = System.currentTimeMillis();
        PurgeState state2 = new PurgeState();
        state2.setPurgeId(purgeId2);
        state2.setPurgeStatus(PurgeStatus.FINISHED_COMPLETE);
        state2.setTimeStamp(TimeUtil.convertToThriftDateTime(System
                .currentTimeMillis()));
        state2.setPurged(Sets.<Long>newHashSet());
        Set<Long> notPurged = Sets.newHashSet();
        notPurged.add(12345l);
        state2.setNotPurged(notPurged);
        state2.setSuggestedPollPeriod(10000);

        ssrService.insertPurgeStatus(state1,
                new Visibility().setFormalVisibility("U"), securityToken);
        ssrService.insertPurgeStatus(state2,
                new Visibility().setFormalVisibility("U"), securityToken);

        PurgeState purgeState = ssrService.purgeStatus(securityToken, purgeId1);
        assertEquals("Should get expected purge1 status", state1.getPurgeStatus(), purgeState.getPurgeStatus());
        purgeState = ssrService.purgeStatus(securityToken, purgeId2);
        assertEquals("Should get expected purge2 status", state2.getPurgeStatus(), purgeState.getPurgeStatus());
        assertEquals("Should get expected purged ids", 0, state2.getPurged().size());
        assertEquals("Should get expected notPurged ids", 1, state2.getNotPurged().size());
        assertEquals("Should get expected suggestedPollPeriod", 10000, state2.getSuggestedPollPeriod());

    }

    @Test
    public void testDelete() throws Exception {
        System.out.println("******** STARTING DELETE TEST");
        populateTestData();

        String uri1 = "DEV://test/tag:search.twitter.com,2005:475858716546592768";
        String uri2 = "DEV://test/tag:search.twitter.com,2005:475858716546596474";

        Set<String> uris = Sets.newHashSet();
        uris.add(uri1);
        uris.add(uri2);

        String queryString = QueryBuilders.matchQuery("title", "ssr_title").toString();
        Query query = new Query().setSearchString(queryString).setPage(new Page().setPageSize((short) 5).setOffset(0));
        SearchResult results = ssrService.search(query, securityToken);
        assertEquals("Should have 2 matching titles before delete", 2, results.getTotalHits());

        ssrService.bulkDelete(uris, securityToken);

        results = ssrService.search(query, securityToken);
        assertEquals("Should have no title matches after delete", 0, results.getTotalHits());
        System.out.println("******** WE'RE DONE");
    }

    @Test
    public void testBeginPurge_NoIds() throws TException {
        long purgeId = System.currentTimeMillis();
        try {
            ssrService.beginPurge("purgeCallbackService", purgeId, Sets.<Long>newHashSet(), securityToken);

            PurgeState purgeState = ssrService.purgeStatus(securityToken, purgeId);

            assertEquals("Should get expected purge FINISHED_COMPLETE status",
                    PurgeStatus.FINISHED_COMPLETE, purgeState.getPurgeStatus());

            ssrService.beginPurge(
                    "purgeCallbackService", purgeId, null, securityToken);

            purgeState = ssrService.purgeStatus(securityToken, purgeId);

            assertEquals("Should get expected purge FINISHED_COMPLETE status",
                    PurgeStatus.FINISHED_COMPLETE, purgeState.getPurgeStatus());
        } catch (TException te) {
            fail("Should not have run into exception");
        }
    }

    @Test
    public void testBeginPurge_BadSecurityToken() throws TException {
        EzSecurityToken badToken = ThriftTestUtils.generateTestSecurityToken(
                "xyz", "xyz", Arrays.asList("U"));
        try {
            ssrService.beginPurge("purgeCallbackService", System.currentTimeMillis(), Sets.<Long>newHashSet(), badToken);
            fail("Should have run into an exception due to bad token");
        } catch (TException te) {
        }
    }

}
