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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.gson.*;

import ezbake.base.thrift.*;
import ezbake.data.common.TimeUtil;
import ezbake.data.elastic.thrift.*;
import ezbake.security.client.EzSecurityTokenWrapper;
import ezbake.security.client.EzbakeSecurityClient;
import ezbake.security.thrift.AppNotRegisteredException;
import ezbake.base.thrift.CancelStatus;
import ezbake.base.thrift.EzSecurityToken;
import ezbake.base.thrift.EzSecurityTokenException;
import ezbake.base.thrift.PurgeException;
import ezbake.base.thrift.PurgeState;
import ezbake.base.thrift.PurgeStatus;
import ezbake.base.thrift.SSR;
import ezbake.base.thrift.Visibility;
import ezbake.services.centralPurge.thrift.ezCentralPurgeServiceConstants;
import ezbake.services.geospatial.thrift.*;
import ezbake.services.provenance.thrift.PositionsToUris;
import ezbake.services.provenance.thrift.ProvenanceService;
import ezbake.services.provenance.thrift.ProvenanceServiceConstants;
import ezbake.services.search.utils.BooleanSerializer;
import ezbake.services.search.utils.SSRUtils;
import ezbake.thrift.ThriftClientPool;
import ezbake.util.AuditEvent;
import ezbake.util.AuditEventType;
import ezbake.util.AuditLogger;
import ezbake.util.AuditLoggerConfigurator;
import ezbakehelpers.ezconfigurationhelpers.application.EzBakeApplicationConfigurationHelper;

import org.apache.commons.collections.map.LRUMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;
import org.elasticsearch.index.query.QueryBuilders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.Date;
import java.util.regex.Pattern;


public class SSRServiceHandler extends EzBakeBasePurgeThriftService implements ssrService.Iface {
    
    private static Logger logger = LoggerFactory.getLogger(SSRServiceHandler.class);
    private Gson gson;
    private JsonParser jsonParser = new JsonParser();
    private ThriftClientPool pool;
    private final LRUMap typeCache = new LRUMap(1000);
    private final String DATE_FACET_KEY = "Report Date";
    private final String VISIBILITY_FACET_KEY = "Report Visibility";
    private final String TYPE_FACET_KEY = "Report Type";
    private final String GEO_COUNTRY_FACET_KEY = "Report Country";
    private final String GEO_PROVINCE_FACET_KEY = "Report State/Province";
    private long last24hoursMS = 0;
    private long last48hoursMS = 0;
    private long last72hoursMS = 0;
    private long last7daysMS = 0;
    private long last30daysMS = 0;
    private long last90daysMS = 0;
    private long last365daysMS = 0;
    private String securityId;
    private static AuditLogger auditLogger;

    // Configuration constants
    public static String EZELASTIC_APPLICATION_NAME_KEY = "ssr.application.name";
    public static String EZELASTIC_SERVICE_NAME_KEY = "ezelastic.service.name";

    private EzbakeSecurityClient security;

    public TProcessor getThriftProcessor() {
        EzElastic.Client documentClient = null;
        try {
            Properties props = getConfigurationProperties();
            pool = new ThriftClientPool(props);
            documentClient = getDocumentClient();
            security = new EzbakeSecurityClient(props);

            // Update the index to ignore malformed values coming in. The malformed values will still be added
            // to _all, but they won't be searchable in their field.
            EzbakeSecurityClient client = new EzbakeSecurityClient(props);
            securityId = new EzBakeApplicationConfigurationHelper(props).getSecurityID();
            EzSecurityToken token = client.fetchAppToken();
            documentClient.closeIndex(token);
            documentClient.applySettings("{\"index\" : {\"mapping\" : {\"ignore_malformed\" : true}}}", token);
            documentClient.openIndex(token);
            try {
                client.close();
            } catch (IOException e) {
                logger.warn("Could not close ezsecurity client. Service restart may be required", e);
            }
            gson = new GsonBuilder()
                    .setDateFormat("ddHHmm'Z' MMM yy")
                    .registerTypeAdapter(Boolean.TYPE, new BooleanSerializer())
                    .create();

            AuditLoggerConfigurator.setAdditivity(true);
            auditLogger = AuditLogger.getAuditLogger(SSRServiceHandler.class);
            
            return new ssrService.Processor(this);
        } catch (AppNotRegisteredException e) {
            logger.error("SSR Service not registered in ezsecurity. Exiting.", e);
            throw new RuntimeException("Could not initialize SSR service", e);
        } catch (TException e) {
            logger.error("Error starting SSR Service.", e);
            throw new RuntimeException("Could not initialize SSR service", e);
        } finally {
            pool.returnToPool(documentClient);
        }
    }

    @Override
    public List<IndexResponse> putWithDocs(Map<SSR, String> ssrJsonMap, EzSecurityToken userToken) throws TException {
        
        List<Document> toIndex = new ArrayList<>();
        EzElastic.Client documentClient = getDocumentClient();
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "putWithDocs");
        security.validateReceivedToken(userToken);
        
        for(Map.Entry<SSR,String> entry : ssrJsonMap.entrySet()) {
            SSR ssr = entry.getKey();
            String type = getTypeFromUri(ssr.getUri());
            if(!typeCache.containsKey(type)) {
                // If it already exists and just isn't in the cache there is no harm
                logger.info("Setting up initial mapping for type ({})", type);
                documentClient.setTypeMapping(type, getSSRTypeMap(type), security.fetchDerivedTokenForApp(userToken, securityId));
                typeCache.put(type, true);
            }
            toIndex.add(generateDocument(ssr, getCombinedJSON(ssr, entry.getValue())));
            auditArgs.put("uri", ssr.getUri());
            auditLog(userToken, AuditEventType.FileObjectCreate, auditArgs);
        }
        
        try {
            return documentClient.bulkPut(toIndex, userToken);
        } catch (DocumentIndexingException e) {
            logger.error("Failed to index records", e);
            throw new TException("Error indexing records - document index exception", e);
        } finally {
            pool.returnToPool(documentClient);
        }
    }

    @Override
    public SearchResult search(Query query, EzSecurityToken userToken) throws TException {
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "search");
        auditArgs.put("query", query.toString());
        auditLog(userToken, AuditEventType.FileObjectAccess, auditArgs);
        security.validateReceivedToken(userToken);
        
        EzElastic.Client documentClient = null;
        try {
            documentClient = getDocumentClient();
            return documentClient.query(query, security.fetchDerivedTokenForApp(userToken, securityId));
        } finally {
            pool.returnToPool(documentClient);
        }
    }

    @Override
    public SSRSearchResult searchSSR(Query query, EzSecurityToken userToken) throws TException {
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "searchSSR");
        auditArgs.put("query", query.toString());
        auditLog(userToken, AuditEventType.FileObjectAccess, auditArgs);
        security.validateReceivedToken(userToken);
        
        SearchResult datasetResults = new SearchResult();
        EzElastic.Client documentClient = getDocumentClient();
        try {
            query.setReturnedFields(ImmutableSet.of(SSRUtils.SSR_FIELD));
            if (!query.isSetFacets()) {
                query.setFacets(new ArrayList<Facet>());
            }
            query.getFacets().addAll(buildSSRFacets());
            datasetResults = documentClient.query(query, security.fetchDerivedTokenForApp(userToken, securityId));
        } catch (MalformedQueryException e) {
            logger.error("Query was malformed");
            throw new TException(e);
        } finally {
            pool.returnToPool(documentClient);
        }
        SSRSearchResult results = new SSRSearchResult();
        results.setTotalHits(datasetResults.getTotalHits());
        results.setPageSize(query.getPage().getPageSize());
        results.setOffset(query.getPage().getOffset());
        results.setMatchingRecords(new ArrayList<SSR>());
        if (datasetResults.isSetHighlights()) {
            results.setHighlights(datasetResults.getHighlights());
        }
        for(Document match : datasetResults.getMatchingDocuments()) {
            String jsonObjectAsString = match.get_jsonObject();
            if(jsonObjectAsString == null) {
                logger.error("Document had no json object");
            }
            JsonElement jsonElement = jsonParser.parse(jsonObjectAsString);
            JsonObject jsonObject = jsonElement.getAsJsonObject();
            JsonElement ssrObject = jsonObject.get(SSRUtils.SSR_FIELD);
            String ssrJson = ssrObject.getAsString();
            SSR ssrResult = gson.fromJson(ssrJson, SSR.class);
            ssrResult.setVisibility(match.getVisibility());
            results.addToMatchingRecords(ssrResult);
        }

        results.setFacets(new HashMap<String, FacetCategory>());

        if(results.getTotalHits() > 0) {
            Map<String, FacetCategory> facetValues = new HashMap<>();

            FacetCategory dateCategory = new FacetCategory();
            dateCategory.setField(SSRUtils.SSR_DATE_FIELD);
            dateCategory.setFacetValues(getDateFacets(datasetResults.getFacets().get(DATE_FACET_KEY)));
            facetValues.put(DATE_FACET_KEY, dateCategory);

            FacetCategory visibilityCategory = new FacetCategory();
            visibilityCategory.setField("ezbake_auths");
            visibilityCategory.setFacetValues(getVisibilityFacets(datasetResults.getFacets().get(VISIBILITY_FACET_KEY)));
            facetValues.put(VISIBILITY_FACET_KEY, visibilityCategory);

            FacetCategory typeCategory = new FacetCategory();
            typeCategory.setField(SSRUtils.SSR_TYPE_FIELD);
            typeCategory.setFacetValues(getTermFacets(datasetResults.getFacets().get(TYPE_FACET_KEY)));
            facetValues.put(TYPE_FACET_KEY, typeCategory);

            FacetCategory countryCategory = new FacetCategory();
            countryCategory.setField(SSRUtils.SSR_COUNTRY_FIELD);
            countryCategory.setFacetValues(getTermFacets(datasetResults.getFacets().get(GEO_COUNTRY_FACET_KEY)));
            facetValues.put(GEO_COUNTRY_FACET_KEY, countryCategory);

            FacetCategory provinceCategory = new FacetCategory();
            provinceCategory.setField(SSRUtils.SSR_PROVINCE_FIELD);
            provinceCategory.setFacetValues(getTermFacets(datasetResults.getFacets().get(GEO_PROVINCE_FACET_KEY)));
            facetValues.put(GEO_PROVINCE_FACET_KEY, provinceCategory);

            results.setFacets(facetValues);
        }

        return results;
    }

    @Override
    public boolean ping() {
        GeospatialExtractorService.Client geoClient = null;
        EzElastic.Client docClient = null;
        try {
            logger.debug("getting document dataset");
            docClient = getDocumentClient();
            logger.debug("getting geo service");
            geoClient = getGeospatialClient();
            boolean result;
            logger.debug("calling ping on doc client");
            result = docClient.ping();
            logger.debug("calling ping on geo client");
            result = result && geoClient.ping();
            return result;
        } catch (TException e) {
            logger.error("SSR ping failed : {}", e.getMessage());
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } finally {
            if (docClient != null) {
                pool.returnToPool(docClient);
            }
            if (geoClient != null) {
                pool.returnToPool(geoClient);
            }
        }
        return false;
    }

    private List<FacetValue> getTermFacets(FacetResult facetResult) {
        List<FacetValue> values = new ArrayList<FacetValue>();

        for(TermsFacetEntry entry : facetResult.getTermsFacetResult().getEntries()) {
            RawValue rawValue = new RawValue();
            rawValue.setStringValue(entry.getTerm());
            values.add(new FacetValue().setLabel(entry.getTerm()).setValue(rawValue).setCount(String.valueOf(entry.getCount())));
        }
        return values;
    }

    private List<FacetValue> getVisibilityFacets(FacetResult facetResult) {
        List<FacetValue> values = new ArrayList<FacetValue>();
        // TODO
        return values;
    }

    private List<FacetValue> getDateFacets(FacetResult facetResult) {
        List<FacetValue> values = new ArrayList<FacetValue>();

        for(RangeFacetEntry entry : facetResult.getRangeFacetResult().getEntries()) {
            RawValue rawValue = new RawValue();
            rawValue.setDoubleValue(Double.valueOf(entry.getFrom()));
            values.add(new FacetValue().setLabel(getTimeWindow(Double.valueOf(entry.getFrom()))).setValue(rawValue).setCount(String.valueOf(entry.getCount())));
        }

        return values;
    }

    private String getTimeWindow(double ms) {
        if(ms <= last365daysMS) {
            return "Last Year";
        }

        if(ms <= last90daysMS) {
            return "Last 90 Days";
        }

        if(ms <= last30daysMS) {
            return "Last 30 Days";
        }

        if(ms <= last7daysMS) {
            return "Last Week";
        }

        if(ms <= last72hoursMS) {
            return "Last 72 Hours";
        }

        if(ms <= last48hoursMS) {
            return "Last 48 Hours";
        }

        return "Last 24 Hours";
    }

    private List<Facet> buildSSRFacets() {
        GregorianCalendar calendar = new GregorianCalendar();
        List<Facet> facets = new ArrayList<Facet>();

        /* Date Facet */
        Facet ssrDateFacet = new Facet();
        RangeFacet dateRangeFacet = new RangeFacet();
        BaseFacetValue dateField = new BaseFacetValue();
        dateField.setFacetField(SSRUtils.SSR_DATE_FIELD);
        dateRangeFacet.setField(dateField);

        FacetRange last24 = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -1);
        last24hoursMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        last24.setFrom(String.valueOf(last24hoursMS));
        dateRangeFacet.addToRanges(last24);

        FacetRange last48 = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -1);
        last48hoursMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        last48.setFrom(String.valueOf(last48hoursMS));
        dateRangeFacet.addToRanges(last48);

        FacetRange last72 = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -1);
        last72hoursMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        last72.setFrom(String.valueOf(last72hoursMS));
        dateRangeFacet.addToRanges(last72);

        FacetRange lastWeek = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -4);
        last7daysMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        lastWeek.setFrom(String.valueOf(last7daysMS));
        dateRangeFacet.addToRanges(lastWeek);

        FacetRange last30Days = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -23);
        last30daysMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        last30Days.setFrom(String.valueOf(last30daysMS));
        dateRangeFacet.addToRanges(last30Days);

        FacetRange last90Days = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -60);
        last90daysMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        last90Days.setFrom(String.valueOf(last90daysMS));
        dateRangeFacet.addToRanges(last90Days);

        FacetRange lastYear = new FacetRange(RangeType.DATE);
        calendar.add(Calendar.DAY_OF_YEAR, -275);
        last365daysMS = DateUtils.round(calendar, Calendar.HOUR).getTimeInMillis();
        lastYear.setFrom(String.valueOf(last365daysMS));
        dateRangeFacet.addToRanges(lastYear);

        FacetRequest dateRequest = new FacetRequest();
        dateRequest.setRangeFacet(dateRangeFacet);

        ssrDateFacet.setLabel(DATE_FACET_KEY);
        ssrDateFacet.setFacet(dateRequest);
        facets.add(ssrDateFacet);
        /* End Date Facet */

        /* Geo Facet via Metacarta */
        TermsFacet countryFacet = new TermsFacet();
        countryFacet.setFields(Arrays.asList(SSRUtils.SSR_COUNTRY_FIELD));

        FacetRequest countryFacetRequest = new FacetRequest();
        countryFacetRequest.setTermsFacet(countryFacet);

        Facet ssrCountryFacet = new Facet();
        ssrCountryFacet.setLabel(GEO_COUNTRY_FACET_KEY);
        ssrCountryFacet.setFacet(countryFacetRequest);
        facets.add(ssrCountryFacet);

        TermsFacet provinceFacet = new TermsFacet();
        provinceFacet.setFields(Arrays.asList(SSRUtils.SSR_PROVINCE_FIELD));

        FacetRequest provinceFacetRequest = new FacetRequest();
        provinceFacetRequest.setTermsFacet(provinceFacet);

        Facet ssrProvinceFacet = new Facet();
        ssrProvinceFacet.setLabel(GEO_PROVINCE_FACET_KEY);
        ssrProvinceFacet.setFacet(provinceFacetRequest);
        facets.add(ssrProvinceFacet);
        /* End Geo Facet */

        /* Type Facet */
        TermsFacet typeFacet = new TermsFacet();
        typeFacet.setFields(Arrays.asList(SSRUtils.SSR_TYPE_FIELD));

        FacetRequest typeFacetRequest = new FacetRequest();
        typeFacetRequest.setTermsFacet(typeFacet);

        Facet ssrTypeFacet = new Facet();
        ssrTypeFacet.setLabel(TYPE_FACET_KEY);
        ssrTypeFacet.setFacet(typeFacetRequest);
        facets.add(ssrTypeFacet);
        /* End Type Facet */

        /* Security Facet */
        TermsFacet securityFacet = new TermsFacet();
        securityFacet.setFields(Arrays.asList("ezbake_auths"));

        FacetRequest securityFacetRequest = new FacetRequest();
        securityFacetRequest.setTermsFacet(securityFacet);

        Facet ssrAuthFacet = new Facet();
        ssrAuthFacet.setLabel(VISIBILITY_FACET_KEY);
        ssrAuthFacet.setFacet(securityFacetRequest);
        facets.add(ssrAuthFacet);
         /* End Security Facet */

        return facets;
    }

    private EzElastic.Client getDocumentClient() throws TException {
        return pool.getClient(getConfigurationProperties().getProperty(EZELASTIC_APPLICATION_NAME_KEY), 
                getConfigurationProperties().getProperty(EZELASTIC_SERVICE_NAME_KEY),
                EzElastic.Client.class);
    }

    private GeospatialExtractorService.Client getGeospatialClient() throws TException {
        return pool.getClient(GeospatialExtractorConstants.SERVICE_NAME, GeospatialExtractorService.Client.class);
    }

    private Document generateDocument(SSR ssr, String json) {
        Document document = new Document();
        document.set_jsonObject(json);
        document.set_id(ssr.getUri());
        // Type should be application + thrift object type
        document.set_type(getTypeFromUri(ssr.getUri()));
        document.setVisibility(ssr.getVisibility());
        return document;
    }

    private String getCombinedJSON(SSR ssr, String jsonDocument) throws TException {
        Map<String, Object> ssrJson = new HashMap<>();
        Map<String, Double> coordMap = new HashMap<>();
        coordMap.put(SSRUtils.ELASTIC_LATITUDE_DEFAULT, ssr.getCoordinate() != null ? ssr.getCoordinate().getLatitude() : 0.0);
        coordMap.put(SSRUtils.ELASTIC_LONGITUDE_DEFAULT, ssr.getCoordinate() != null ? ssr.getCoordinate().getLongitude() : 0.0);
        ssrJson.put(SSRUtils.SSR_DATE_FIELD, ssr.getResultDate() != null ? new Date(TimeUtil.convertFromThriftDateTime(ssr.getResultDate())) : null);
        ssrJson.put(SSRUtils.SSR_COORDINATE_FIELD, coordMap);
        ssrJson.put(SSRUtils.SSR_TYPE_FIELD, getTypeFromUri(ssr.getUri()));
        ssrJson.put(SSRUtils.SSR_FIELD, SSRUtils.convertThriftToJson(ssr));
        ssrJson.put(SSRUtils.SSR_METADATA_FIELD, ssr.getMetaData() != null ? ssr.getMetaData().getTags() : null);

        if(ssr.getCoordinate() != null) {
            GeospatialExtractorService.Client geoClient = getGeospatialClient();
            try {
                TLocationFinderResult geoLocation = geoClient
                        .findLocation(new TCentroid(ssr.getCoordinate().getLatitude(),
                                ssr.getCoordinate().getLongitude()), null);
                if(!geoLocation.getLocations().isEmpty()) {
                    // Find the location with the most administrative paths
                    List<String> administrativePaths = getMostAccurateLocation(geoLocation.getLocations());
                    if(!administrativePaths.isEmpty()) {
                        ssrJson.put(SSRUtils.SSR_COUNTRY_FIELD, administrativePaths.get(administrativePaths.size() - 1));
                        if(administrativePaths.size() > 1) {
                            ssrJson.put(SSRUtils.SSR_PROVINCE_FIELD, administrativePaths.get(administrativePaths.size() - 2));
                        }
                        logger.info("SSR being indexed based on geospatial locations : {}",
                                StringUtils.join(administrativePaths, ", "));
                    }
                }
            } finally {
                pool.returnToPool(geoClient);
            }
        }

        String ssrStripped = gson.toJson(ssrJson)
                .replaceFirst(Pattern.quote("{"), StringUtils.EMPTY);
        return jsonDocument.substring(0, jsonDocument.lastIndexOf("}"))+ "," + ssrStripped;
    }

    private List<String> getMostAccurateLocation(List<TLocation> locations) {
        List<String> results = new ArrayList<String>();
        for(TLocation location : locations) {
            if(location.getPaths().getAdministrativeSize() > results.size()) {
                results = location.getPaths().getAdministrative();
            }
        }
        return results;
    }

    protected String getTypeFromUri(String uri) {
        String type = uri.replace("://", ":");
        return type.substring(0, type.indexOf("/"));
    }

    protected static String getSSRTypeMap(String type) {
        return "{\n" +
                "    \"" + type + "\" : {\n" +
                "        \"properties\" : {\n" +
                "            \"" + SSRUtils.SSR_COORDINATE_FIELD + "\" : {\n" +
                "                \"type\" : \"geo_point\",\n" +
                "                \"lat_lon\" : true\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_DATE_FIELD + "\" : {\n" +
                "                \"type\" : \"date\",\n" +
                "                \"format\" : \"ddHHmm'Z' MMM yy\",\n" +
                "                \"store\" : true\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"no\"\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_TYPE_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"not_analyzed\"\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_COUNTRY_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"not_analyzed\"\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_PROVINCE_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"not_analyzed\"\n" +
                "            },\n" +
                "            \"" + SSRUtils.SSR_METADATA_FIELD + "\" : {\n" +
                "                \"type\" : \"object\",\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"not_analyzed\"\n" +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}";
    }
    
    // purge implementation

    /**
     * Deletes documents with given set of ids (uris, more specifically) from the elastic database.
     *
     * @param uriList set of URIs to delete from SSR
     * @param userToken the token of the user or service initiating this request
     */
    protected void bulkDelete(Set<String> uriList, EzSecurityToken userToken) throws TException {
        EzElastic.Client documentClient = getDocumentClient();
        try {
            documentClient.bulkDelete(uriList, security.fetchDerivedTokenForApp(userToken, securityId));
        } finally {
            pool.returnToPool(documentClient);
        }
    }

    protected class SSRDeleterRunnable implements Runnable {
        private Set<Long> idsToPurge;
        private EzSecurityToken userToken;
        private long purgeId;

        public SSRDeleterRunnable(Set<Long> idsToPurge, EzSecurityToken userToken, long purgeId) {
            this.idsToPurge = idsToPurge;
            this.userToken = userToken;
            this.purgeId = purgeId;
        }

        @Override
        public void run() {
            Visibility visibility = new Visibility();
            // TODO revisit the visibility level to use
            visibility.setFormalVisibility(userToken.getAuthorizationLevel());
            try {
                PurgeState state = purgeStatus(userToken, purgeId);
                try {

                    if (!(state.getCancelStatus() == CancelStatus.CANCELED && state.getPurgeStatus() == PurgeStatus.ERROR
                            && state.getPurgeStatus() == PurgeStatus.FINISHED_COMPLETE)) {
                        Set<String> uriList = getPurgeUris(idsToPurge, userToken);
                        bulkDelete(uriList, userToken);

                        // Purge completed, update the status object
                        state.setPurgeStatus(PurgeStatus.FINISHED_COMPLETE);
                        state.setTimeStamp(TimeUtil.convertToThriftDateTime(System.currentTimeMillis()));
                        state.setPurged(idsToPurge);
                        state.setNotPurged(Sets.<Long>newHashSet());
                    }
                } catch (Exception e) {
                    logger.error(
                            "The delete of the URIs from the ssr index failed. The requesting purgeId is '"
                                    + purgeId + "'.", e);
                    state.setPurgeStatus(PurgeStatus.ERROR);
                }
                insertPurgeStatus(state, visibility, userToken);
            } catch (EzSecurityTokenException e) {
                logger.error("Could not retrieve chained security token for delete operation", e);
            } catch (TException e) {
                logger.error("Purge could not complete successfully", e);
            }
        }
    }

    @Override
    public PurgeState beginVirusPurge(String purgeCallbackService, long purgeId, 
            Set<Long> idsToPurge, EzSecurityToken userToken)
            throws PurgeException, EzSecurityTokenException, TException {
        return this.beginPurge(purgeCallbackService, purgeId, idsToPurge, userToken);
    }

    /**
     * Always returns a {@link CancelStatus#CANNOT_CANCEL} status and does
     * not cancel previously started purges from ezElastic.
     */
    @Override
    public PurgeState cancelPurge(EzSecurityToken userToken, long purgeId)
            throws EzSecurityTokenException, TException {
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "cancelPurge");
        auditArgs.put("purgeId", Long.toString(purgeId));
        auditLog(userToken, AuditEventType.FileObjectDelete, auditArgs);

        validateEzCentralPurgeSecurityId(userToken);

        PurgeState state = purgeStatus(userToken, purgeId); // TODO
        state.setCancelStatus(CancelStatus.CANNOT_CANCEL);
        state.setTimeStamp(TimeUtil.convertToThriftDateTime(System.currentTimeMillis()));
        insertPurgeStatus(state, new Visibility().setFormalVisibility(userToken.getAuthorizationLevel()), userToken);
        
        return state;
    }

    @Override
    public PurgeState beginPurge(String purgeCallbackService, long purgeId,
            Set<Long> idsToPurge, EzSecurityToken userToken)
            throws PurgeException, EzSecurityTokenException, TException {
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "beginPurge");
        auditArgs.put("purgeId", Long.toString(purgeId));
        auditLog(userToken, AuditEventType.FileObjectDelete, auditArgs);

        validateEzCentralPurgeSecurityId(userToken);
        boolean emptyPurgeIds = idsToPurge == null || idsToPurge.isEmpty();
        
        Visibility visibility = new Visibility();
        // TODO revisit the visibility level to use
        visibility.setFormalVisibility(userToken.getAuthorizationLevel());
        
        PurgeState state = new PurgeState();
        state.setPurgeId(purgeId);
        state.setPurgeStatus(PurgeStatus.STARTING);
        state.setTimeStamp(TimeUtil.convertToThriftDateTime(System.currentTimeMillis()));
        state.setPurged(Sets.<Long>newHashSet());
        state.setNotPurged(idsToPurge);
        state.setSuggestedPollPeriod(10000);
        if (emptyPurgeIds) {
            logger.info("No ids were given for purge. Marking the purge as finished.");
            state.setPurgeStatus(PurgeStatus.FINISHED_COMPLETE);
        }

        insertPurgeStatus(state, visibility, userToken);

        // Checking emptyPurgeIds twice because we want the start up of the deleter thread
        // to be the absolute last thing we do before returning
        if (!emptyPurgeIds) {
            new Thread(new SSRDeleterRunnable(idsToPurge, userToken, purgeId)).start();
        }
        return state;
    }

    @Override
    public PurgeState purgeStatus(EzSecurityToken userToken, long purgeId)
            throws EzSecurityTokenException, TException {
        HashMap<String, String> auditArgs = Maps.newHashMap();
        auditArgs.put("action", "purgeStatus");
        auditArgs.put("purgeId", Long.toString(purgeId));
        auditLog(userToken, AuditEventType.FileObjectAccess, auditArgs);

        validateEzCentralPurgeSecurityId(userToken);
        
        PurgeState state = new PurgeState();
        state.setPurgeId(purgeId);
        state.setPurgeStatus(PurgeStatus.UNKNOWN_ID);
        state.setTimeStamp(TimeUtil.convertToThriftDateTime(System.currentTimeMillis()));
        Set<Long> emptySet = Sets.newHashSet();
        state.setPurged(emptySet);
        state.setNotPurged(emptySet);
        state.setSuggestedPollPeriod(10000);

        String queryStr = QueryBuilders.matchQuery("purgeId", purgeId).toString();
        Query query = new Query();
        query.setSearchString(queryStr);
        query.setType(SSRUtils.PURGE_TYPE_FIELD);
        
        ezbake.data.elastic.thrift.SearchResult purgeResults;
        EzElastic.Client documentClient = getDocumentClient();
        try {
            purgeResults = documentClient.query(query, security.fetchDerivedTokenForApp(userToken, securityId));
        } catch (MalformedQueryException e) {
            logger.error("Purge query was malformed.", e);
            throw new TException(e);
        } finally {
            pool.returnToPool(documentClient);
        }

        if (purgeResults.getMatchingDocuments().size() > 0) {
            Document match = purgeResults.getMatchingDocuments().get(0);
            String jsonObjectAsString = match.get_jsonObject();
            if(jsonObjectAsString == null) {
                logger.error("Document had no json object");
            }
            JsonElement jsonElement = jsonParser.parse(jsonObjectAsString);
            state = gson.fromJson(jsonElement, PurgeState.class);
        }
        
        return state;
    }

    /**
     * Retrieves the document URIs corresponding to given IDs from the
     * Provenance service.
     * 
     * @param idsToPurge set of IDs to purge whose URIs we are seeking
     * @param userToken security token
     * @return set of document URIs 
     * @throws TException if any error occurs
     */
    private Set<String> getPurgeUris(Set<Long> idsToPurge,
            EzSecurityToken userToken) throws TException {

        ProvenanceService.Client client = null;
        try {
            client = pool.getClient(ProvenanceServiceConstants.SERVICE_NAME,
                    ProvenanceService.Client.class);
            ArrayList<Long> idsToPurgeList = new ArrayList<>();
            idsToPurgeList.addAll(idsToPurge);
            EzSecurityTokenWrapper chained = security.fetchDerivedTokenForApp(userToken, pool.getSecurityId(ProvenanceServiceConstants.SERVICE_NAME));
            PositionsToUris uriPositions = client.getDocumentUriFromId(chained, idsToPurgeList);

            Map<Long, String> map = uriPositions.getMapping();
            Collection<String> uris = map.values();

            return uris == null ? new HashSet<String>() : new HashSet<>(uris);
        } finally {
            pool.returnToPool(client);
        }
    }
    
    /**
     * Inserts a purge status into the elastic database via the ezElastic
     * service.
     * 
     * @param purgeState containing the purge id, status, time, etc.
     * @param visibility visibility of the purge.
     * @param userToken security token.
     * @throws TException if any error occurs
     */
    void insertPurgeStatus(PurgeState purgeState, Visibility visibility,
            EzSecurityToken userToken) throws TException {
        
        EzElastic.Client documentClient = getDocumentClient();

        if(!typeCache.containsKey(SSRUtils.PURGE_TYPE_FIELD)) {
            // If it already exists and just isn't in the cache there is no harm
            logger.info("Setting up initial mapping for purge type ({})", SSRUtils.PURGE_TYPE_FIELD);
            documentClient.setTypeMapping("purge:type", getPurgeTypeMap(), security.fetchDerivedTokenForApp(userToken, securityId));
            typeCache.put(SSRUtils.PURGE_TYPE_FIELD, true);
        }
        
        String json = gson.toJson(purgeState);

        Document document = new Document();
        document.set_jsonObject(json);
        document.set_id(String.valueOf(purgeState.getPurgeId()));
        document.set_type(SSRUtils.PURGE_TYPE_FIELD);
        document.setVisibility(visibility);

        try {
            List<IndexResponse> result = Lists.newArrayList();
            IndexResponse response = documentClient.put(document, security.fetchDerivedTokenForApp(userToken, securityId));
            if (!response.isSuccess()) {
                logger.error("Put failed for purge status with id {}", response.get_id());
                result.add(response);
            }
        } catch (DocumentIndexingException e) {
            logger.error("Failed to index purge status", e);
            throw new TException("Error indexing purge status - document index exception", e);
        } finally {
            pool.returnToPool(documentClient);
        }
    }

    /**
     * Creates an elasticsearch mapping specifically for the purge state persistence, 
     * distinct from the ssr mapping. Used to separate purge state data
     * from ssr search queries.
     * 
     * @return purge type mapping string for elasticsearch.
     */
    private String getPurgeTypeMap() {
        return "{\n" +
                "    \"" + SSRUtils.PURGE_TYPE_FIELD + "\" : {\n" +
                "    \"_all\" : {\"enabled\" : false}, \n" +
                "        \"properties\" : {\n" +
                "            \"" + SSRUtils.PURGE_ID_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"include_in_all\" : false,\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"no\"\n" +
                "            },\n" +
                "            \"" + SSRUtils.PURGE_STATE_FIELD + "\" : {\n" +
                "                \"type\" : \"string\",\n" +
                "                \"include_in_all\" : false,\n" +
                "                \"store\" : true,\n" +
                "                \"index\" : \"no\"\n" +
                "            }\n" +
                "        }\n" +
                "    }\n" +
                "}";
    }
    
    /**
     * Validates that the app security from the userToken matches up the
     * EzCentralPurgeService security id.
     * @param userToken
     * @throws TException thrown if the security Id does not match up.
     */
    private void validateEzCentralPurgeSecurityId(EzSecurityToken userToken) throws TException {
        security.validateReceivedToken(userToken);
        String purgeSecurityId = pool.getSecurityId(ezCentralPurgeServiceConstants.SERVICE_NAME);
        
        EzSecurityTokenWrapper tokenWrapper = new EzSecurityTokenWrapper(userToken);
        String appSecurityId = tokenWrapper.getSecurityId();
        
        if ((purgeSecurityId != null) && (!purgeSecurityId.equals(appSecurityId))) {
            throw new TException("The app security id does not match up with the"
                    + " EzCentralPurgeService security id");
        }
    }

    @Override
    public void shutdown() {
        pool.close();
        try {
            if (security != null) {
                security.close();
            }
        } catch (IOException e) {
            logger.warn("Could not properly close security client", e);
        }
    }

    private void auditLog(EzSecurityToken userToken, AuditEventType eventType, 
            Map<String, String> args) {
        AuditEvent event = new AuditEvent(eventType, userToken);
        for (String argName : args.keySet()) {
            event.arg(argName, args.get(argName));
        }
        if (auditLogger != null) {
            auditLogger.logEvent(event);
        }
    }
}
