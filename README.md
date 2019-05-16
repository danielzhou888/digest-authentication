
[TOC]

The tools supports PUT、POST、DELETE、GET methods to digest anthentication;
You can get result info by json or xml data with switch type;

#### 什么是摘要认证
摘要认证（ Digest authentication）是一个简单的认证机制，最初是为HTTP协议开发的，因而也常叫做HTTP摘要，在RFC2617中描述。其身份验证机制很简单，它采用杂凑式（hash）加密方法，以避免用明文传输用户的口令。

摘要认证就是要核实，参与通信的双方，都知道双方共享的一个秘密（即口令）。
![image.png](https://upload-images.jianshu.io/upload_images/14119490-439a2d0d15c513bf.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

##### 服务器核实用户身份
server收到client的HTTP request（INVITE），如果server需要客户端摘要认证，就需要生成一个摘要盘问（digest challenge），通过Response给client一个401 Unauthorized状态发送给用户。
摘要盘问如 图二 中的WWW-Authenticate header所示：

- ![image.png](https://upload-images.jianshu.io/upload_images/14119490-29ba60f2a6b44642.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**摘要盘问中的各个参数意义如下：**

- realm（领域）：必须的，在所有的盘问中都必须有。它是目的是鉴别SIP消息中的机密。在实际应用中，它通常设置为server所负责的域名。

- nonce （现时）：必须的，这是由服务器规定的数据字符串，在服务器每次产生一个摘要盘问时，这个参数都是不一样的（与前面所产生的不会雷同）。nonce 通常是由一些数据通过md5杂凑运算构造的。这样的数据通常包括时间标识和服务器的机密短语。确保每个nonce 都有一个有限的生命期（也就是过了一些时间后会失效，并且以后再也不会使用），而且是独一无二的（即任何其它的服务器都不能产生一个相同的nonce ）。

- Stale：不必须，一个标志，用来指示客户端先前的请求因其nonce值过期而被拒绝。如果stale是TRUE（大小写敏感），客户端可能希望用新的加密回应重新进行请求，而不用麻烦用户提供新的用户名和口令。服务器端只有在收到的请求nonce值不合法，而该nonce对应的摘要（digest）是合法的情况下（即客户端知道正确的用户名/口令），才能将stale置成TRUE值。如果stale是FALSE或其它非TRUE值，或者其stale域不存在，说明用户名、口令非法，要求输入新的值。

- opaque（不透明体）：必须的，这是一个不透明的（不让外人知道其意义）数据字符串，在盘问中发送给用户。

- algorithm（算法）：不必须，这是用来计算杂凑的算法。当前只支持MD5算法。

- qop（保护的质量）：必须的，这个参数规定服务器支持哪种保护方案。客户端可以从列表中选择一个。值 “auth”表示只进行身份查验， “auth-int”表示进行查验外，还有一些完整性保护。需要看更详细的描述，请参阅[RFC2617](http://www.faqs.org/rfcs/rfc2617.html)。


##### 客户端反馈用户身份
client 生成 生成摘要响应（digest response），然后再次通过 http request （INVITE （Withink digest））发给 server。

摘要响应如 图三 中的Authenticate header所示：

- ![image.png](https://upload-images.jianshu.io/upload_images/14119490-011791816f3bde92.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**摘要响应中的各个参数意义如下：**

- username： 不用再说明了
- realm： 需要和 server 盘问的realm保持一致
- nonce：客户端使用这个“现时”来产生摘要响应（digest response），需要和server 盘问中携带的nonce保持一致，这样服务器也会在一个摘要响应中收到“现时”的内容。服务器先要检查了“现时”的有效性后，才会检查摘要响应的其它部分。
因而，nonce 在本质上是一种标识符，确保收到的摘要机密，是从某个特定的摘要盘问产生的。还限制了摘要盘问的生命期，防止未来的重播攻击。

- qop：客户端选择的保护方式。

- nc （现时计数器）：这是一个16进制的数值，即客户端发送出请求的数量（包括当前这个请求），这些请求都使用了当前请求中这个“现时”值。例如，对一个给定的“现时”值，在响应的第一个请求中，客户端将发送“nc=00000001”。这个指示值的目的，是让服务器保持这个计数器的一个副本，以便检测重复的请求。如果这个相同的值看到了两次，则这个请求是重复的。

- response：这是由用户代理软件计算出的一个字符串，以证明用户知道口令。比如可以通过 username、password、http method、uri、以及nonce、qop等使用MD5加密生成。

- cnonce：这也是一个不透明的字符串值，由客户端提供，并且客户端和服务器都会使用，以避免用明文文本。这使得双方都可以查验对方的身份，并对消息的完整性提供一些保护。

- uri：这个参数包含了客户端想要访问的URI。


##### server 确认用户
确认用户主要由两部分构成：

- 检查nonce的有效性
- 检查摘要响应中的其他信息， 比如server可以按照和客户端同样的算法生成一个response值，和client传递的response进行对比。

#### 代码示例
**HttpRequestUtils工具类**
```java
package com.asy.http.client;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;  
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;  
import java.io.IOException;  
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;  
import java.net.URLConnection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Http Digest Request contains POST、GET、PUT
 * @author zhouzhixiang
 * @date 2019-05-14
 */
public class HttpRequestUtils {

    private static final Logger logger = LoggerFactory.getLogger(HttpRequestUtils.class);

    public static void main(String[] args) {
        // String url = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications/live/publishers";
        // String url = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications/Relay/streamfiles/1234566/actions/connect?&vhost=_defaultVHost_&appType=live&appName=Relay&appInstance=_definst_&connectAppName=Relay&connectAppInstance=_definst_&streamFile=1234566.stream&mediaCasterType=liverepeater";
        String param = "";
        String username = "xxxxxx";
        String password = "xxxxxx";
        // String json = "{ \"password\": \"plmo13579123\", \"publisherName\": \"4\", \"serverName\": \"_defaultServer_\", \"description\": \"\", \"saveFieldList\": [ \"\" ], \"version\": \"v1.0\" }";
        // String s = sendPost(url, param, username, password, json);

        // String s = sendPost(url, param, username, password, json);

        // -----------------GET-success------------------
        String getUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications";
        // String s = sendGet(getUrl, param, username, password, null);
        // -----------------GET-success------------------

        // -----------------PUT-success------------------
        String putUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/vhosts/_defaultVHost_/applications/Relay/streamfiles/6D07D7E7623B95889C33DC5901307461_0/actions/connect";
        String putJson = "{ \"vhost\":\"_defaultVHost_\", \"mediaCasterType\":\"liverepeater\" }";
        // String s = sendPUT(putUrl, param, username, password, putJson, null);
        // -----------------PUT-success------------------

        // -----------------POST-success------------------
        String postUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/users";
        String postJson = "{ \"password\": \"123456\", \"serverName\": \"_defaultServer_\", \"description\": \"\", \"groups\": [ \"\" ], \"saveFieldList\": [ \"\" ], \"userName\": \"test6\", \"version\": \"v1.0\" }";
        // String s = sendPost(postUrl, param, username, password, postJson, null);
        // -----------------POST-success------------------

        // -----------------POST-success------------------
        String postUrl2 = "http://192.168.200.117:8087/v2/servers/_defaultServer_/publishers";
        String postJson2 = "{ \"password\": \"1579655633@qq.com\", \"name\": \"test11\", \"serverName\": \"_defaultServer_\", \"description\": \"test\", \"saveFieldList\": [ \"\" ], \"version\": \"v1.0\" }";
        // String s = sendPost(postUrl2, param, username, password, postJson2, null);
        // -----------------POST-success------------------

        // -----------------DELETE-success------------------
        String deleteUrl = "http://192.168.200.117:8087/v2/servers/_defaultServer_/users/test5";
        // String deleteJson = "{ \"password\": \"1579655633@qq.com\", \"name\": \"test11\", \"serverName\": \"_defaultServer_\", \"description\": \"test\", \"saveFieldList\": [ \"\" ], \"version\": \"v1.0\" }";
        String s = sendDelete(deleteUrl, param, username, password, null, null);
        // -----------------DELETE-success------------------

        System.out.println(s);
    }

    static int nc = 0;    //调用次数
    private static final String GET = "GET";
    private static final String POST = "POST";
    private static final String PUT = "PUT";
    private static final String DELETE = "DELETE";

    /**
     * 向指定URL发送DELETE方法的请求
     * @param url                                   发送请求的URL
     * @param param                                 请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @param username                              验证所需的用户名
     * @param password                              验证所需的密码
     * @param json                                  请求json字符串
     * @param type                                  返回xml和json格式数据，默认xml，传入json返回json数据
     * @return URL                                  所代表远程资源的响应结果
     */
    public static String sendDelete(String url, String param, String username, String password, String json, String type) {

        StringBuilder result = new StringBuilder();
        BufferedReader in = null;
        try {
            String wwwAuth = sendGet(url, param);       //发起一次授权请求
            if (wwwAuth.startsWith("WWW-Authenticate:")) {
                wwwAuth = wwwAuth.replaceFirst("WWW-Authenticate:", "");
            } else {
                return wwwAuth;
            }
            nc ++;
            String urlNameString = url + (StringUtils.isNotEmpty(param) ? "?" + param : "");
            URL realUrl = new URL(urlNameString);
            // 打开和URL之间的连接
            HttpURLConnection connection = (HttpURLConnection)realUrl.openConnection();

            // 设置是否向connection输出，因为这个是post请求，参数要放在
            // http正文内，因此需要设为true
            connection.setDoOutput(true);
            // Read from the connection. Defaultis true.
            connection.setDoInput(true);
            // 默认是 GET方式
            connection.setRequestMethod(DELETE);

            // 设置通用的请求属性
            setRequestProperty(connection, wwwAuth, realUrl, username, password, DELETE, type);

            if (!StringUtils.isEmpty(json)) {
                byte[] writebytes =json.getBytes();
                connection.setRequestProperty("Content-Length",String.valueOf(writebytes.length));
                OutputStream outwritestream = connection.getOutputStream();
                outwritestream.write(json.getBytes());
                outwritestream.flush();
                outwritestream.close();
            }

            if (connection.getResponseCode() == 200) {
                in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    result.append(line);
                }
            } else {
                String errResult = formatResultInfo(connection, type);
                logger.info(errResult);
                return errResult;
            }

            nc = 0;
        } catch (Exception e) {
            nc = 0;
            throw new RuntimeException(e);
        } finally {
            try {
                if (in != null) in.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result.toString();
    }



    /**
     * 向指定URL发送PUT方法的请求
     * @param url                                      发送请求的URL
     * @param param                                    请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @param username                                 验证所需的用户名
     * @param password                                 验证所需的密码
     * @param json                                     请求json字符串
     * @param type                                     返回xml和json格式数据，默认xml，传入json返回json数据
     * @return URL                                     所代表远程资源的响应结果
     */
    public static String sendPUT(String url, String param, String username, String password, String json, String type) {

        StringBuilder result = new StringBuilder();
        BufferedReader in = null;
        try {
            String wwwAuth = sendGet(url, param);       //发起一次授权请求
            if (wwwAuth.startsWith("WWW-Authenticate:")) {
                wwwAuth = wwwAuth.replaceFirst("WWW-Authenticate:", "");
            } else {
                return wwwAuth;
            }
            nc ++;
            String urlNameString = url + (StringUtils.isNotEmpty(param) ? "?" + param : "");
            URL realUrl = new URL(urlNameString);
            // 打开和URL之间的连接
            HttpURLConnection connection = (HttpURLConnection)realUrl.openConnection();

            // 设置是否向connection输出，因为这个是post请求，参数要放在
            // http正文内，因此需要设为true
            connection.setDoOutput(true);
            // Read from the connection. Defaultis true.
            connection.setDoInput(true);
            // 默认是 GET方式
            connection.setRequestMethod(PUT);
            // Post 请求不能使用缓存
            connection.setUseCaches(false);

            // 设置通用的请求属性
            setRequestProperty(connection, wwwAuth,realUrl, username, password, PUT, type);

            if (!StringUtils.isEmpty(json)) {
                byte[] writebytes =json.getBytes();
                connection.setRequestProperty("Content-Length",String.valueOf(writebytes.length));
                OutputStream outwritestream = connection.getOutputStream();
                outwritestream.write(json.getBytes());
                outwritestream.flush();
                outwritestream.close();
            }

            if (connection.getResponseCode() == 200) {
                in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    result.append(line);
                }
            } else {
                String errResult = formatResultInfo(connection, type);
                logger.info(errResult);
                return errResult;
            }

            nc = 0;
        } catch (Exception e) {
            nc = 0;
            throw new RuntimeException(e);
        } finally {
            try {
                if (in != null) in.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result.toString();
    }

    /**
     * 向指定URL发送POST方法的请求
     * @param url                                       发送请求的URL
     * @param param                                     请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @param username                                  验证所需的用户名
     * @param password                                  验证所需的密码
     * @param json                                      请求json字符串
     * @param type                                      返回xml和json格式数据，默认xml，传入json返回json数据
     * @return URL 所代表远程资源的响应结果
     */
    public static String sendPost(String url, String param, String username, String password, String json, String type) {

        StringBuilder result = new StringBuilder();
        BufferedReader in = null;
        try {
            String wwwAuth = sendGet(url, param);       //发起一次授权请求
            if (wwwAuth.startsWith("WWW-Authenticate:")) {
                wwwAuth = wwwAuth.replaceFirst("WWW-Authenticate:", "");
            } else {
                return wwwAuth;
            }
            nc ++;
            String urlNameString = url + (StringUtils.isNotEmpty(param) ? "?" + param : "");
            URL realUrl = new URL(urlNameString);
            // 打开和URL之间的连接
            HttpURLConnection connection = (HttpURLConnection)realUrl.openConnection();

            // 设置是否向connection输出，因为这个是post请求，参数要放在
            // http正文内，因此需要设为true
            connection.setDoOutput(true);
            // Read from the connection. Defaultis true.
            connection.setDoInput(true);
            // 默认是 GET方式
            connection.setRequestMethod(POST);
            // Post 请求不能使用缓存
            connection.setUseCaches(false);

            // 设置通用的请求属性
            setRequestProperty(connection, wwwAuth,realUrl, username, password, POST, type);

            if (!StringUtils.isEmpty(json)) {
                byte[] writebytes =json.getBytes();
                connection.setRequestProperty("Content-Length",String.valueOf(writebytes.length));
                OutputStream outwritestream = connection.getOutputStream();
                outwritestream.write(json.getBytes());
                outwritestream.flush();
                outwritestream.close();
            }
            if (connection.getResponseCode() == 200 || connection.getResponseCode() == 201) {
                in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                while ((line = in.readLine()) != null) {
                    result.append(line);
                }
            } else {
                String errResult = formatResultInfo(connection, type);
                logger.info(errResult);
                return errResult;
            }

            nc = 0;
        } catch (Exception e) {
            nc = 0;
            throw new RuntimeException(e);
        } finally {
            try {
                if (in != null) in.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result.toString();
    }


    /** 
     * 向指定URL发送GET方法的请求 
     * @param url                                       发送请求的URL
     * @param param                                     请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @param username                                  验证所需的用户名
     * @param password                                  验证所需的密码
     * @param type                                      返回xml和json格式数据，默认xml，传入json返回json数据
     * @return URL 所代表远程资源的响应结果
     */  
    public static String sendGet(String url, String param, String username, String password, String type) {
  
        StringBuilder result = new StringBuilder();  
        BufferedReader in = null;  
        try {  
            String wwwAuth = sendGet(url, param);       //发起一次授权请求
            if (wwwAuth.startsWith("WWW-Authenticate:")) {  
                wwwAuth = wwwAuth.replaceFirst("WWW-Authenticate:", "");  
            } else {  
                return wwwAuth;  
            }  
            nc ++;
            String urlNameString = url + (StringUtils.isNotEmpty(param) ? "?" + param : "");
            URL realUrl = new URL(urlNameString);  
            // 打开和URL之间的连接
            HttpURLConnection connection = (HttpURLConnection)realUrl.openConnection();
            // 设置通用的请求属性
            setRequestProperty(connection, wwwAuth,realUrl, username, password, GET, type);
            // 建立实际的连接
            // connection.connect();
            in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String line;  
            while ((line = in.readLine()) != null) {  
                result.append(line);  
            }  
            nc = 0;
        } catch (Exception e) {  
            nc = 0;  
            throw new RuntimeException(e);  
        } finally {  
            try {  
                if (in != null) in.close();  
            } catch (Exception e2) {  
                e2.printStackTrace();  
            }  
        }  
        return result.toString();  
    }  
  
    /**  
     * 生成授权信息  
     * @param authorization                             上一次调用返回401的WWW-Authenticate数据
     * @param username                                  用户名
     * @param password                                  密码
     * @return                                          授权后的数据, 应放在http头的Authorization里
     * @throws IOException                              异常
     */  
    private static String getAuthorization(String authorization, String uri, String username, String password, String method) throws IOException {
  
        uri = StringUtils.isEmpty(uri) ? "/" : uri;  
        // String temp = authorization.replaceFirst("Digest", "").trim();
        String temp = authorization.replaceFirst("Digest", "").trim().replace("MD5","\"MD5\"");
        // String json = "{\"" + temp.replaceAll("=", "\":").replaceAll(",", ",\"") + "}";
        String json = withdrawJson(authorization);
        // String json = "{ \"realm\": \"Wowza\", \" domain\": \"/\", \" nonce\": \"MTU1NzgxMTU1NzQ4MDo2NzI3MWYxZTZkYjBiMjQ2ZGRjYTQ3ZjNiOTM2YjJjZA==\", \" algorithm\": \"MD5\", \" qop\": \"auth\" }";

        JSONObject jsonObject = JSON.parseObject(json);  
        // String cnonce = new String(Hex.encodeHex(Digests.generateSalt(8)));    //客户端随机数
        String cnonce = Digests.generateSalt2(8);
        String ncstr = ("00000000" + nc).substring(Integer.toString(nc).length());     //认证的次数,第一次是1，第二次是2...  
        // String algorithm = jsonObject.getString("algorithm");
        String algorithm = jsonObject.getString("algorithm");
        String qop = jsonObject.getString("qop");
        String nonce = jsonObject.getString("nonce");
        String realm = jsonObject.getString("realm");

        String response = Digests.http_da_calc_HA1(username, realm, password,
                nonce, ncstr, cnonce, qop,
                method, uri, algorithm);
  
        //组成响应authorization  
        authorization = "Digest username=\"" + username + "\"," + temp;  
        authorization += ",uri=\"" + uri  
                + "\",nc=\"" + ncstr  
                + "\",cnonce=\"" + cnonce  
                + "\",response=\"" + response+"\"";  
        return authorization;  
    }

    /**
     * 将返回的Authrization信息转成json
     * @param authorization                                     authorization info
     * @return                                                  返回authrization json格式数据 如：String json = "{ \"realm\": \"Wowza\", \" domain\": \"/\", \" nonce\": \"MTU1NzgxMTU1NzQ4MDo2NzI3MWYxZTZkYjBiMjQ2ZGRjYTQ3ZjNiOTM2YjJjZA==\", \" algorithm\": \"MD5\", \" qop\": \"auth\" }";
     */
    private static String withdrawJson(String authorization) {
        String temp = authorization.replaceFirst("Digest", "").trim().replaceAll("\"","");
        // String noncetemp = temp.substring(temp.indexOf("nonce="), temp.indexOf("uri="));
        // String json = "{\"" + temp.replaceAll("=", "\":").replaceAll(",", ",\"") + "}";
        String[] split = temp.split(",");
        Map<String, String> map = new HashMap<>();
        Arrays.asList(split).forEach(c -> {
            String c1 = c.replaceFirst("=",":");
            String[] split1 = c1.split(":");
            map.put(split1[0].trim(), split1[1].trim());
        });
        return JSONObject.toJSONString(map);
    }

    /** 
     * 向指定URL发送GET方法的请求 
     * @param url                                                   发送请求的URL
     * @param param                                                 请求参数，请求参数应该是 name1=value1&name2=value2 的形式。
     * @return URL                                                  所代表远程资源的响应结果
     */  
    public static String sendGet(String url, String param) {  
        StringBuilder result = new StringBuilder();  
        BufferedReader in = null;  
        try {  
  
            String urlNameString = url + (StringUtils.isNotEmpty(param) ? "?" + param : "");
            URL realUrl = new URL(urlNameString);  
            // 打开和URL之间的连接  
            URLConnection connection = realUrl.openConnection();  
            // 设置通用的请求属性  
            connection.setRequestProperty("accept", "*/*");  
            connection.setRequestProperty("connection", "Keep-Alive");  
            connection.setRequestProperty("user-agent",  
                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");  
  
            connection.connect();  
  
            //返回401时需再次用用户名和密码请求  
            //此情况返回服务器的 WWW-Authenticate 信息  
            if (((HttpURLConnection) connection).getResponseCode() == 401) {  
                Map<String, List<String>> map = connection.getHeaderFields();  
                return "WWW-Authenticate:" + map.get("WWW-Authenticate").get(0);  
            }  
  
            in = new BufferedReader(new InputStreamReader(connection.getInputStream()));  
            String line;  
            while ((line = in.readLine()) != null) {  
                result.append(line);  
            }  
        } catch (Exception e) {  
            throw new RuntimeException("get请求发送失败",e);  
        }  
        // 使用finally块来关闭输入流  
        finally {  
            try {  
                if (in != null) in.close();  
            } catch (Exception e2) {  
                e2.printStackTrace();  
            }  
        }  
        return result.toString();  
    }

    /**
     * HTTP set request property
     *
     * @param connection                            HttpConnection
     * @param wwwAuth                               授权auth
     * @param realUrl                               实际url
     * @param username                              验证所需的用户名
     * @param password                              验证所需的密码
     * @param method                                请求方式
     * @param type                                  返回xml和json格式数据，默认xml，传入json返回json数据
     */
    private static void setRequestProperty(HttpURLConnection connection, String wwwAuth, URL realUrl, String username, String password, String method, String type)
        throws IOException {

        if (type != null && type.equals("json")) {
            // 返回json
            connection.setRequestProperty("accept", "application/json;charset=UTF-8");
            connection.setRequestProperty("Content-Type","application/json;charset=UTF-8");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent",
                                          "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
        } else {
            // 返回xml
            if (!method.equals(GET)) {
                connection.setRequestProperty("Content-Type","application/json;charset=UTF-8");
            }
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            // connection.setRequestProperty("Cache-Control", "no-cache");
            connection.setRequestProperty("user-agent",
                                          "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");

        }
        //授权信息
        String authentication = getAuthorization(wwwAuth, realUrl.getPath(), username, password, method);
        connection.setRequestProperty("Authorization", authentication);
    }

    /**
     * 格式化请求返回信息，支持json和xml格式
     * @param connection                                HttpConnection
     * @param type                                      指定返回数据格式，json、xml，默认xml
     * @return                                          返回数据
     */
    private static String formatResultInfo(HttpURLConnection connection, String type) throws IOException {
        String result = "";
        if (type != null && type.equals("json")) {
            result = String.format("{\"errCode\":%s, \"message\":%s}",connection.getResponseCode(),connection.getResponseMessage());
        } else {
            result = String.format(" <?xml version=\"1.0\" encoding=\"UTF-8\" ?> "
                                       + " <wmsResponse>"
                                       + " <errCode>%d</errCode>"
                                       + " <message>%s</message>"
                                       + " </wmsResponse>",connection.getResponseCode(),connection.getResponseMessage());
        }
        return result;
    }

}  
```


```java
package com.asy.http.client;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.Validate;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Http Digest
 * @author zhouzhixiang
 * @date 2019-05-14
 */
public class Digests {

    private static SecureRandom random = new SecureRandom();
    /**
     * 加密遵循RFC2671规范 将相关参数加密生成一个MD5字符串,并返回
     */
    public static String http_da_calc_HA1(String username, String realm, String password,
        String nonce, String nc, String cnonce, String qop,
        String method, String uri, String algorithm) {
        String HA1, HA2;
        if ("MD5-sess".equals(algorithm)) {
            HA1 = HA1_MD5_sess(username, realm, password, nonce, cnonce);
        } else {
            HA1 = HA1_MD5(username, realm, password);
        }
        byte[] md5Byte = md5(HA1.getBytes());
        HA1 = new String(Hex.encodeHex(md5Byte));

        md5Byte = md5(HA2(method, uri).getBytes());
        HA2 = new String(Hex.encodeHex(md5Byte));

        String original = HA1 + ":" + (nonce + ":" + nc + ":" + cnonce + ":" + qop) + ":" + HA2;

        md5Byte = md5(original.getBytes());
        return new String(Hex.encodeHex(md5Byte));

    }

    /**
     * algorithm值为MD5时规则
     */
    private static String HA1_MD5(String username, String realm, String password) {
        return username + ":" + realm + ":" + password;
    }

    /**
     * algorithm值为MD5-sess时规则
     */
    private static String HA1_MD5_sess(String username, String realm, String password, String nonce, String cnonce) {
        //      MD5(username:realm:password):nonce:cnonce

        String s = HA1_MD5(username, realm, password);
        byte[] md5Byte = md5(s.getBytes());
        String smd5 = new String(Hex.encodeHex(md5Byte));

        return smd5 + ":" + nonce + ":" + cnonce;
    }

    private static String HA2(String method, String uri) {
        return method + ":" + uri;
    }

    /**
     * 对输入字符串进行md5散列.
     */
    public static byte[] md5(byte[] input) {
        return digest(input, "MD5", null, 1);
    }

    /**
     * 对字符串进行散列, 支持md5与sha1算法.
     */
    private static byte[] digest(byte[] input, String algorithm, byte[] salt, int iterations) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            if (salt != null) {
                digest.update(salt);
            }

            byte[] result = digest.digest(input);

            for (int i = 1; i < iterations; i++) {
                digest.reset();
                result = digest.digest(result);
            }
            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 随机生成numBytes长度数组
     * @param numBytes
     * @return
     */
    public static byte[] generateSalt(int numBytes) {
        Validate.isTrue(numBytes > 0, "numBytes argument must be a positive integer (1 or larger)", (long)numBytes);
        byte[] bytes = new byte[numBytes];
        random.nextBytes(bytes);
        return bytes;
    }

    @Deprecated
    public static String generateSalt2(int length) {
        String val = "";
        Random random = new Random();
        //参数length，表示生成几位随机数
        for(int i = 0; i < length; i++) {
            String charOrNum = random.nextInt(2) % 2 == 0 ? "char" : "num";
            //输出字母还是数字
            if( "char".equalsIgnoreCase(charOrNum) ) {
                //输出是大写字母还是小写字母
                int temp = random.nextInt(2)%2 == 0 ? 65 : 97;
                val += (char)(random.nextInt(26) + temp);
            } else if( "num".equalsIgnoreCase(charOrNum) ) {
                val += String.valueOf(random.nextInt(10));
            }
        }
        return val.toLowerCase();
    }


    //测试
    public static void main(String[] args) throws UnsupportedEncodingException {
        // String s = http_da_calc_HA1("povodo", "realm@easycwmp", "povodo",
        //                             "c10c9897f05a9aee2e2c5fdebf03bb5b0001b1ef", "00000001", "d5324153548c43d8", "auth",
        //                             "GET", "/", "MD5");
        // System.out.println("加密后response为:" + s);

        // String s = new String(generateSalt(8),"UTF-8");

        // System.out.println(s);
    }
}
```

**测试类：**
```java
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
```

**pom.xml**

```java
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.asy.sample</groupId>
    <artifactId>digest-authentication</artifactId>
    <version>1.0-SNAPSHOT</version>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>1.5.7.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <source>8</source>
                    <target>8</target>
                </configuration>
            </plugin>
        </plugins>
    </build>


    <dependencies>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jetty</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>

        <dependency>
            <groupId>org.apache.httpcomponents</groupId>
            <artifactId>httpclient</artifactId>
            <version>4.5.1</version>
        </dependency>

        <!-- https://mvnrepository.com/artifact/org.apache.commons/commons-lang3 -->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.9</version>
        </dependency>

        <!-- https://mvnrepository.com/artifact/com.alibaba/fastjson -->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.58</version>
        </dependency>

        <!-- xml to json -->
        <dependency>
            <groupId>net.sf.json-lib</groupId>
            <artifactId>json-lib</artifactId>
            <version>2.4</version>
            <classifier>jdk15</classifier>
        </dependency>
        <dependency>
            <groupId>xom</groupId>
            <artifactId>xom</artifactId>
            <version>1.2.5</version>
        </dependency>

        <dependency>
            <groupId>xom</groupId>
            <artifactId>xom</artifactId>
            <version>1.2.5</version>
            <classifier>sources</classifier>
        </dependency>
        <!-- xml to json -->

    </dependencies>


</project>
```

本文参考 [HTTP Digest authentication](https://blog.csdn.net/andrewpj/article/details/45727853)

