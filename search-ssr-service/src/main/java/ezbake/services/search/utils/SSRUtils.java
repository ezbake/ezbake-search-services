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

package ezbake.services.search.utils;

import org.apache.thrift.TBase;
import org.apache.thrift.TException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TSimpleJSONProtocol;

public abstract class SSRUtils {

    public static final String SSR_DATE_FIELD = "_ssr_date";
    public static final String SSR_COORDINATE_FIELD = "_ssr_coordinates";
    public static final String SSR_PROVINCE_FIELD = "_ssr_province";
    public static final String SSR_COUNTRY_FIELD = "_ssr_country";
    public static final String SSR_TYPE_FIELD = "_ssr_type";
    public static final String SSR_METADATA_FIELD = "_ssr_metadata";
    public static final String SSR_FIELD = "_ssr";

    public static final String ELASTIC_LONGITUDE_DEFAULT = "lon";
    public static final String ELASTIC_LATITUDE_DEFAULT = "lat";
    
    public static final String PURGE_TYPE_FIELD = "purge:type";
    public static final String PURGE_ID_FIELD = "purge:id";
    public static final String PURGE_STATE_FIELD = "purge:state";

    private SSRUtils() {}

    public static String convertThriftToJson(TBase thriftObject) throws TException {
        TSerializer serializer = new TSerializer(new TSimpleJSONProtocol.Factory());
        return serializer.toString(thriftObject, "UTF-8");
    }
}
