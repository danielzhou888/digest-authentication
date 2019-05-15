package com.asy.http.test;

import com.asy.http.client.HttpRequestUtils;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Http Digest Request contains POST、GET、PUT
 * @author zhouzhixiang
 * @date 2019-05-14
 */
public class HttpRequestUtilsTest {

    private static final Logger logger = LoggerFactory.getLogger(HttpRequestUtilsTest.class);

    private static final String PARAM = "";
    private static final String USERNAME = "xxxxxx";
    private static final String PASSWORD = "xxxxxx";

    @Test
    public void testSendGet() {
        String getUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications";
        // String s = HttpRequestUtils.sendGet(getUrl, PARAM, USERNAME, PASSWORD, null);
        String s = HttpRequestUtils.sendGet(getUrl, PARAM, USERNAME, PASSWORD, "json");
        logger.info(s);
        Assert.assertNotNull(s);
    }

    @Test
    public void testSendDelete() {
        String deleteUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/users/test6";
    //     String s = sendDelete(deleteUrl, param, username, password, null, null);
    //     String s = HttpRequestUtils.sendDelete(deleteUrl, PARAM, USERNAME, PASSWORD, null,"json");
        String s = HttpRequestUtils.sendDelete(deleteUrl, PARAM, USERNAME, PASSWORD, null,null);
        logger.info(s);
        Assert.assertNotNull(s);
    }

    @Test
    public void testSendPost() {
        String postUrl2 = "http://192.168.200.117:8087/v2/servers/_defaultServer_/publishers";
        String postJson2 = "{ \"password\": \"1579655633@qq.com\", \"name\": \"test15\", \"serverName\": \"_defaultServer_\", \"description\": \"test\", \"saveFieldList\": [ \"\" ], \"version\": \"v1.0\" }";
        // 返回json
        String s = HttpRequestUtils.sendPost(postUrl2, PARAM, USERNAME, PASSWORD, postJson2, "json");
        // 返回xml
        // String s = HttpRequestUtils.sendPost(postUrl2, PARAM, USERNAME, PASSWORD, postJson2, null);
        logger.info(s);
        Assert.assertNotNull(s);
    }

    @Test
    public void testSendPUT() {
        String putUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications/Relay/streamfiles/6D07D7E7623B95889C33DC5901307461_0/actions/connect";
        String putJson = "{ \"vhost\":\"_defaultVHost_\", \"mediaCasterType\":\"liverepeater\" }";
        // String s = HttpRequestUtils.sendPUT(putUrl, PARAM, USERNAME, PASSWORD, putJson, "json");
        String s = HttpRequestUtils.sendPUT(putUrl, PARAM, USERNAME, PASSWORD, putJson, null);
        logger.info(s);
        Assert.assertNotNull(s);
    }

}
