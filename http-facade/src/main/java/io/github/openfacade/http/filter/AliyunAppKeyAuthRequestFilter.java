/*
 * Copyright 2024 OpenFacade Authors
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
 */

package io.github.openfacade.http.filter;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import io.github.openfacade.http.HttpRequest;
import io.github.openfacade.http.RequestFilter;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;

import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AliyunAppKeyAuthRequestFilter implements RequestFilter {

    public static final String METHOD = "HmacSHA256";

    private final String appKey;
    private final String appSecret;

    public AliyunAppKeyAuthRequestFilter(String appKey, String appSecret) {
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    private static String getHttpDateHeaderValue(Date date) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.format(date);
    }

    @SneakyThrows
    private static Date getDateFromHttpHeaderValue(String dateHeaderValue) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.parse(dateHeaderValue);
    }

    @Override
    public HttpRequest filter(HttpRequest request) {
        Date current;
        //设置请求头中的时间戳
        String dateHeaderValue = request.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE);
        if (null == dateHeaderValue) {
            current = new Date();
            request.addHeader(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE, getHttpDateHeaderValue(current));
        } else {
            current = getDateFromHttpHeaderValue(dateHeaderValue);
        }

        //设置请求头中的时间戳，以timeIntervalSince1970的形式
        request.addHeader(SdkConstant.CLOUDAPI_X_CA_TIMESTAMP, String.valueOf(current.getTime()));

        if(null == request.getFirstHeaderValue(SdkConstant.CLOUDAPI_X_CA_NONCE)) {
            request.addHeader(SdkConstant.CLOUDAPI_X_CA_NONCE, UUID.randomUUID().toString());
        }

        //设置请求头中的UserAgent
        request.addHeader(HttpConstant.CLOUDAPI_HTTP_HEADER_USER_AGENT, SdkConstant.CLOUDAPI_USER_AGENT);

        // TODO 设置请求头中的主机地址
//        request.addHeader(HttpConstant.CLOUDAPI_HTTP_HEADER_HOST , request.getHost());

        //设置请求头中的Api绑定的的AppKey
        request.addHeader(SdkConstant.CLOUDAPI_X_CA_KEY, appKey);

        //设置签名版本号
        request.addHeader(SdkConstant.CLOUDAPI_X_CA_VERSION , SdkConstant.CLOUDAPI_CA_VERSION_VALUE);

        //设置请求数据类型
        if(null == request.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE)) {
            request.addHeader(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE, HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON);
        }
        //设置应答数据类型
        if(null == request.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT)){
            request.addHeader(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT , HttpConstant.CLOUDAPI_CONTENT_TYPE_JSON);
        }
        request.addHeader(SdkConstant.CLOUDAPI_X_CA_SIGNATURE_METHOD, METHOD);

        String signature =sign(request, appSecret);
        request.addHeader(SdkConstant.CLOUDAPI_X_CA_SIGNATURE, signature);

        return request;
    }

    private String sign(HttpRequest request, String appSecret) {
        String signString = buildStringToSign(request);
        if (StringUtils.isEmpty(signString)) {
            throw new IllegalArgumentException("strToSign can not be empty");
        }

        if (StringUtils.isEmpty(appSecret)) {
            throw new IllegalArgumentException("secretKey can not be empty");
        }

        byte[] result = Hashing.hmacSha256(appSecret.getBytes(SdkConstant.CLOUDAPI_ENCODING))
                .hashBytes(signString.getBytes(SdkConstant.CLOUDAPI_ENCODING)).asBytes();
        return Base64.getEncoder().encodeToString(result);
    }

    public static String buildStringToSign(HttpRequest httpRequest) {
        StringBuilder sb = new StringBuilder();
        sb.append(httpRequest.method().name()).append(SdkConstant.CLOUDAPI_LF);

        //如果有@"Accept"头，这个头需要参与签名
        if (httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT) != null) {
            sb.append(httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_ACCEPT));
        }
        sb.append(SdkConstant.CLOUDAPI_LF);

        //如果有@"Content-MD5"头，这个头需要参与签名
        if (httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_MD5) != null) {
            sb.append(httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_MD5));
        }
        sb.append(SdkConstant.CLOUDAPI_LF);

        //如果有@"Content-Type"头，这个头需要参与签名
        if (httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE) != null) {
            sb.append(httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_CONTENT_TYPE));
        }
        sb.append(SdkConstant.CLOUDAPI_LF);

        //签名优先读取HTTP_CA_HEADER_DATE，因为通过浏览器过来的请求不允许自定义Date（会被浏览器认为是篡改攻击）
        if (httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE) != null) {
            sb.append(httpRequest.getFirstHeaderValue(HttpConstant.CLOUDAPI_HTTP_HEADER_DATE));
        }
        sb.append(SdkConstant.CLOUDAPI_LF);

        //将headers合成一个字符串
        sb.append(buildHeaders(httpRequest));

        //将path、queryParam、formParam合成一个字符串
        sb.append(buildResource(httpRequest));

        return sb.toString();
    }

    /**
     *  将headers合成一个字符串
     *  需要注意的是，HTTP头需要按照字母排序加入签名字符串
     *  同时所有加入签名的头的列表，需要用逗号分隔形成一个字符串，加入一个新HTTP头@"X-Ca-Signature-Headers"
     */
    private static String buildHeaders(HttpRequest httpRequest) {
        //使用TreeMap,默认按照字母排序
        Map<String, String> headersToSign = new TreeMap<>();


        StringBuilder signHeadersStringBuilder = new StringBuilder();

        int flag = 0;
        for (Map.Entry<String, List<String>> header : httpRequest.headers().entrySet()) {
            if (header.getKey().startsWith(SdkConstant.CLOUDAPI_CA_HEADER_TO_SIGN_PREFIX_SYSTEM)) {
                if (flag != 0) {
                    signHeadersStringBuilder.append(",");
                }
                flag++;
                signHeadersStringBuilder.append(header.getKey());
                headersToSign.put(header.getKey(), httpRequest.getFirstHeaderValue(header.getKey()));
            }
        }

        //同时所有加入签名的头的列表，需要用逗号分隔形成一个字符串，加入一个新HTTP头@"X-Ca-Signature-Headers"
        httpRequest.addHeader(SdkConstant.CLOUDAPI_X_CA_SIGNATURE_HEADERS, signHeadersStringBuilder.toString());


        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headersToSign.entrySet()) {
            sb.append(e.getKey()).append(':').append(e.getValue()).append(SdkConstant.CLOUDAPI_LF);
        }
        return sb.toString();
    }    /**
     * 将path、queryParam、formParam合成一个字符串
     */
    private static String buildResource(HttpRequest request) {
        StringBuilder result = new StringBuilder();
        // TODO
//        result.append(request.getPath());

        //使用TreeMap,默认按照字母排序
        TreeMap<String , String> parameter = new TreeMap<String , String>();
        if(null!= request.queryParams() && !request.queryParams().isEmpty()){
            for(Map.Entry<String , List<String>> entry : request.queryParams().entrySet()){
                if(entry.getValue() != null) {
                    parameter.put(entry.getKey(), entry.getValue().get(0));
                }
            }
        }

        if(!parameter.isEmpty()) {
            result.append("?");
            boolean isFirst = true;
            for (String key : parameter.keySet()) {
                if (isFirst == false) {
                    result.append("&");
                } else {
                    isFirst = false;
                }
                result.append(key);
                String value = parameter.get(key);
                if(null != value && !"".equals(value)){
                    result.append("=").append(value);
                }
            }
        }
        return result.toString();
    }


}
