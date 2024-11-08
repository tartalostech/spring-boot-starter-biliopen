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
 * <p>
 * The {@code ArchiveUtil} class implements request signing for Bilibili Open Platform.
 * It provides a fluent API to build and send signed HTTP requests using the {@code sendRequestWithSignature} method.
 * </p>
 *
 * <p>
 * Example usage:
 * </p>
 *
 * <pre>{@code
 * ArchiveUtil archiveUtil = new ArchiveUtil("your_client_id", "your_client_secret");
 * JsonNode response = archiveUtil.sendRequestWithSignature()
 *     .method(HttpMethod.POST)
 *     .uri(new URI("https://api.bilibili.com/endpoint"))
 *     .accessToken("your_access_token")
 *     .body(requestBody)
 *     .contentType(MediaType.APPLICATION_JSON)
 *     .execute();
 * }</pre>
 *
 * @author wosiwq
 */
@Slf4j
public class ArchiveUtil {

    private final String CLIENT_ID;
    private final String CLIENT_SECRET;
    private final RestClient restClient = RestClient.create();

    /**
     * Constructs an {@code ArchiveUtil} instance with the specified client ID and client secret.
     *
     * @param clientID     the client ID provided by Bilibili Open Platform
     * @param clientSecret the client secret provided by Bilibili Open Platform
     */
    public ArchiveUtil(String clientID, String clientSecret) {
        this.CLIENT_ID = clientID;
        this.CLIENT_SECRET = clientSecret;
    }

    /**
     * Creates a new request builder to send a signed HTTP request.
     *
     * @return a {@code MethodStage} interface to initiate the request building process
     */
    public MethodStage sendRequestWithSignature() {
        return new RequestBuilder();
    }

    /**
     * Constructs the basic HTTP headers required for the request, including signature headers.
     *
     * @param accessToken the access token for authentication
     * @param body        the request body
     * @param contentType the content type of the request
     * @return an {@code HttpHeaders} object containing all necessary headers
     * @throws NoSuchAlgorithmException if the specified algorithm does not exist
     * @throws InvalidKeyException      if the given key is inappropriate for initializing the Mac
     */
    private HttpHeaders getBasicHttpHeaders(String accessToken, Object body, MediaType contentType)
            throws NoSuchAlgorithmException, InvalidKeyException {
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
     * Generates the Authorization signature string based on the provided headers and client secret.
     *
     * @param headers         the HTTP headers used in the request
     * @param accessKeySecret the client secret
     * @return the generated signature string
     * @throws NoSuchAlgorithmException if the specified algorithm does not exist
     * @throws InvalidKeyException      if the given key is inappropriate for initializing the Mac
     */
    private String createSignature(HttpHeaders headers, String accessKeySecret)
            throws NoSuchAlgorithmException, InvalidKeyException {
        List<String> keyList = new ArrayList<>(headers.keySet());
        // Sort the header keys case-insensitively
        keyList.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder sign = new StringBuilder();
        for (String key : keyList) {
            String value = headers.getFirst(key);
            sign.append(key).append(":").append(value).append("\n");
        }
        // Remove the last newline character
        if (!sign.isEmpty()) {
            sign.setLength(sign.length() - 1);
        }
        return hmacSHA256(accessKeySecret, sign.toString());
    }

    /**
     * Encrypts data using the HMAC-SHA256 algorithm.
     *
     * @param key  the secret key used for encryption
     * @param data the data to be encrypted
     * @return the encrypted data as a hexadecimal string
     * @throws NoSuchAlgorithmException if the specified algorithm does not exist
     * @throws InvalidKeyException      if the given key is inappropriate for initializing the Mac
     */
    private String hmacSHA256(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] hash = sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return the resulting hexadecimal string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            // Convert each byte to a two-digit hexadecimal string
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Computes the MD5 checksum of a given string.
     *
     * @param str the input string
     * @return the MD5 checksum as a hexadecimal string
     */
    private String md5(String str) {
        return DigestUtils.md5DigestAsHex(str.getBytes(StandardCharsets.UTF_8));
    }

    // Define interfaces for the builder pattern stages

    /**
     * The initial stage of the request builder where the HTTP method is specified.
     */
    public interface MethodStage {
        /**
         * Sets the HTTP method for the request.
         *
         * @param method the HTTP method (GET, POST, etc.)
         * @return the next stage of the builder to set the URI
         */
        UriStage method(HttpMethod method);
    }

    /**
     * The stage of the request builder where the URI is specified.
     */
    public interface UriStage {
        /**
         * Sets the URI for the request.
         *
         * @param uri the target URI
         * @return the next stage of the builder to set the access token
         */
        AccessTokenStage uri(URI uri);
    }

    /**
     * The stage of the request builder where the access token is specified.
     */
    public interface AccessTokenStage {
        /**
         * Sets the access token for authentication.
         *
         * @param accessToken the access token
         * @return the next stage of the builder to set the request body
         */
        BodyStage accessToken(String accessToken);
    }

    /**
     * The stage of the request builder where the request body is specified.
     */
    public interface BodyStage {
        /**
         * Sets the body of the request.
         *
         * @param body the request body
         * @return the next stage of the builder to set the content type
         */
        ContentTypeStage body(Object body);
    }

    /**
     * The stage of the request builder where the content type is specified.
     */
    public interface ContentTypeStage {
        /**
         * Sets the content type of the request.
         *
         * @param contentType the content type (e.g., application/json)
         * @return the final stage of the builder to execute the request
         */
        ExecuteStage contentType(MediaType contentType);
    }

    /**
     * The final stage of the request builder where the request is executed.
     */
    public interface ExecuteStage {
        /**
         * Executes the built request and returns the response.
         *
         * @return the response as a {@code JsonNode}
         */
        JsonNode execute();
    }

    /**
     * <p>
     * The {@code RequestBuilder} class provides a fluent API to build and execute HTTP requests
     * with the necessary Bilibili Open Platform signatures.
     * </p>
     *
     * <p>
     * It implements multiple interfaces corresponding to different stages of the request building process.
     * </p>
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
                log.error("Request failed", e);
                throw new RuntimeException("Request failed", e);
            }
        }
    }
}
