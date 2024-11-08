package io.github.tartalostech.utils;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.DigestUtils;
import org.springframework.web.client.RestClient;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * ArchiveUtil 实现了B站开放平台的请求签名，通过sendRequestWithSignature方法即可直接发送签名后的请求。
 */
@Slf4j
public class ArchiveUtil {

    private final String CLIENT_ID;
    private final String CLIENT_SECRET;
    private final RestClient restClient = RestClient.create();

    /**
     * 构造函数，初始化客户端 ID 和客户端密钥。
     *
     * @param clientID     客户端 ID
     * @param clientSecret 客户端密钥
     */
    public ArchiveUtil(String clientID, String clientSecret) {
        this.CLIENT_ID = clientID;
        this.CLIENT_SECRET = clientSecret;
    }

    /**
     * 创建一个新的请求构建器。
     *
     * @return 方法阶段接口，用于链式调用
     */
    public MethodStage sendRequestWithSignature() {
        return new RequestBuilder();
    }

    /**
     * 获取基本的 HTTP 头部信息，包括签名等。
     *
     * @param accessToken 访问令牌
     * @param body        请求体
     * @param contentType 内容类型
     * @return HttpHeaders 对象
     * @throws NoSuchAlgorithmException 当算法不存在时抛出
     * @throws InvalidKeyException      当密钥无效时抛出
     */
    private HttpHeaders getBasicHttpHeaders(String accessToken, Object body, MediaType contentType) throws NoSuchAlgorithmException, InvalidKeyException {
        HttpHeaders headers = new HttpHeaders();
        headers.add("x-bili-timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        headers.add("x-bili-signature-method", "HMAC-SHA256");
        headers.add("x-bili-signature-nonce", UUID.randomUUID().toString());
        headers.add("x-bili-accesskeyid", CLIENT_ID);
        headers.add("x-bili-signature-version", "2.0");
        headers.add("x-bili-content-md5", md5(body == null ? "" : body.toString()));
        headers.add("Authorization", createSignature(headers, CLIENT_SECRET));
        headers.setContentType(contentType);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Access-Token", accessToken);
        return headers;
    }

    /**
     * 生成 Authorization 签名字符串。
     *
     * @param headers         HTTP 头部
     * @param accessKeySecret 客户端密钥
     * @return 签名字符串
     * @throws NoSuchAlgorithmException 当算法不存在时抛出
     * @throws InvalidKeyException      当密钥无效时抛出
     */
    private String createSignature(HttpHeaders headers, String accessKeySecret) throws NoSuchAlgorithmException, InvalidKeyException {
        List<String> keyList = new ArrayList<>(headers.keySet());
        // 对头部键进行不区分大小写的排序
        keyList.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder sign = new StringBuilder();
        for (String key : keyList) {
            String value = headers.getFirst(key);
            sign.append(key).append(":").append(value).append("\n");
        }
        // 移除最后一个换行符
        if (!sign.isEmpty()) {
            sign.setLength(sign.length() - 1);
        }
        return hmacSHA256(accessKeySecret, sign.toString());
    }

    /**
     * 使用 HMAC-SHA256 算法进行加密。
     *
     * @param key  密钥
     * @param data 要加密的数据
     * @return 加密后的十六进制字符串
     * @throws NoSuchAlgorithmException 当算法不存在时抛出
     * @throws InvalidKeyException      当密钥无效时抛出
     */
    private String hmacSHA256(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] hash = sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * 将字节数组转换为十六进制字符串。
     *
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            // 每个字节转换为两位十六进制字符串
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * 计算字符串的 MD5 值。
     *
     * @param str 输入字符串
     * @return MD5 值的十六进制字符串
     */
    private String md5(String str) {
        return DigestUtils.md5DigestAsHex(str.getBytes(StandardCharsets.UTF_8));
    }

    // 定义各个阶段的接口
    public interface MethodStage {
        UriStage method(HttpMethod method);
    }


    public interface UriStage {
        AccessTokenStage uri(URI uri);
    }

    public interface AccessTokenStage {
        BodyStage accessToken(String accessToken);
    }

    public interface BodyStage {
        ContentTypeStage body(Object body);
    }

    public interface ContentTypeStage {
        ExecuteStage contentType(MediaType contentType);
    }

    public interface ExecuteStage {
        JsonNode execute();
    }

    /**
     * 请求构建器类，用于通过链式调用设置请求参数。
     */
    private class RequestBuilder implements MethodStage, UriStage, AccessTokenStage, BodyStage, ContentTypeStage, ExecuteStage {
        private HttpMethod method;
        private URI uri;
        private String accessToken;
        private Object body;
        private MediaType contentType;

        @Override
        public UriStage method(HttpMethod method) {
            this.method = method;
            return this;
        }

        @Override
        public AccessTokenStage uri(URI uri) {
            this.uri = uri;
            return this;
        }

        @Override
        public BodyStage accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        @Override
        public ContentTypeStage body(Object body) {
            this.body = body;
            return this;
        }

        @Override
        public ExecuteStage contentType(MediaType contentType) {
            this.contentType = contentType;
            return this;
        }

        @Override
        public JsonNode execute() {
            try {
                HttpHeaders headers = getBasicHttpHeaders(accessToken, body, contentType);

                RestClient.RequestBodySpec requestSpec = restClient.method(method)
                        .uri(uri)
                        .headers(httpHeaders -> httpHeaders.addAll(headers));

                if (body != null) {
                    requestSpec = requestSpec.body(body);
                }

                return requestSpec.retrieve()
                        .body(JsonNode.class);
            } catch (Exception e) {
                log.error("请求失败", e);
                throw new RuntimeException("请求失败", e);
            }
        }
    }
}
