## 说明
本项目为哔哩哔哩开放平台文档中各项接口的`Spring Boot`版签名实现案例，用于验证签名以及基础请求示例。  
开放平台相关文档请访问：[接口签名实现标准](https://open.bilibili.com/doc/4/8673959e-f7bb-56e6-6e68-d225f971b81b)

## 使用范围
本签名示例的覆盖范围为[哔哩哔哩开放平台文档中心](https://open.bilibili.com/doc)
中相关接口的签名实现，不包含[直播创作者服务中心](https://open-live.bilibili.com/document/bdb1a8e5-a675-5bfe-41a9-7a7163f75dbf#h1-u5E73u53F0u4ECBu7ECD)
中的相关接口，请注意。

## 使用方法
### 添加 spring-boot-starter-biliopen 依赖

```xml
<dependency>
    <groupId>io.github.tartalostech</groupId>
    <artifactId>spring-boot-starter-biliopen</artifactId>
    <version>0.0.1</version>
</dependency>
```

### 示例代码
```java
import com.fasterxml.jackson.databind.JsonNode;
import io.github.tartalostech.utils.ArchiveUtil;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.net.URI;

/**
 * 本示例内容为虚构内容，请根据从开放平台获取的到的实际内容进行填写
 * 实例化 `io.github.tartalostech.utils` 包下的ArchiveUtil类
 * 该类接收两个参数，这两个参数分别为哔哩哔哩开放平台应用的 `client_id` 与 `client_secret`
 */
ArchiveUtil archiveUtil = new ArchiveUtil("your_client_id", "your_client_secret");
/**
 * 链式调用archiveUtil.sendRequestWithSignature函数并传递相应的值
 * 如果不需要body 可以传递.body(null)
 * 在调用execute函数之后会返回jackson的JsonNode对象
 */
JsonNode response = archiveUtil.sendRequestWithSignature()
        .method(HttpMethod.POST)
        .uri(new URI("https://member.bilibili.com/arcopen/fn/live/room/ws-start"))
        .accessToken("your_access_token")
        .body(null)
        .contentType(MediaType.APPLICATION_JSON)
        .execute();
JsonNode data = response.get("data");
String connId = data.get("conn_id").asText();
```

### 请求规范
**接入前请确保已入驻开放平台，且创建开放平台应用以获取`client_id`和`app_secret`**
**需使用B站侧提供的签名算法及header头信息进行返回；**
**加密时`client_id`和`app_secret`以B站侧提供的信息为准；**



### 签名算法

#### 公共参数

下表描述的公共请求头（Request Header）适用于通过URL发送HTTP请求调用API。

| **名称**                 | **类型** | **是否必填** | **描述**                                                     |
| ------------------------ | -------- | ------------ | ------------------------------------------------------------ |
| Accept                   | String   | 是           | 接受的返回结果的类型。目前只支持JSON类型。取值：`application/json` |
| Content-Type             | String   | 是           | 当前请求体（Request Body）的数据类型。取值：`application/json`或`multipart/form-data` |
| x-bili-content-md5       | String   | 是           | 请求体的编码值，根据请求体计算所得(全小写字母)。算法说明：将请求体内容当作字符串进行`MD5`编码。 |
| x-bili-timestamp         | String   | 是           | unix时间戳，单位是秒。请求时间戳不能超过当前时间10分钟，否则请求会被丢弃。 |
| x-bili-signature-method  | String   | 是           | 签名方式。取值：`HMAC-SHA256`                                |
| x-bili-signature-nonce   | String   | 是           | 全网签名唯一随机数。用于防止网络重放攻击，建议您每一次请求都使用不同的随机数，例如GUID。 |
| x-bili-accesskeyid       | String   | 是           | B站侧给出的`Access Key`(申请应用时获得的client_id)                                        |
| x-bili-signature-version | String   | 是           | 支持`1.0`和`2.0`，`1.0`仅用于历史兼容，如无特殊必要，请使用`2.0` |
|access-token|String|否|`x-bili-signature-version`为`2.0`时必填，为通过OAuth2授权获取到的access_token|
| Authorization            | String   | 是           | 请求签名。关于请求签名的计算方法，请参见签名机制。           |

#### 签名算法

签名算法使用HMAC-SHA256



#### 编码格式

请求必须为UTF-8编码


#### 签名机制

##### 1.构建完整的待签名字符串

抽取带"x-bili-"前缀的自定义header，按字典排序拼接，构建完整的待签名字符串：
注：待签名字符串包含换行符`\n`,如果为`GET`请求或者请求的`body`为空，请直接使用`空字符串(string.Empty)`进行求md5

```Plain-text
"x-bili-accesskeyid:$accesskeyidValue"
"x-bili-content-md5:$contentMd5Value"
"x-bili-signature-method:HMAC-SHA256"
"x-bili-signature-nonce:$signatureNonceValue"
"x-bili-signature-version:1.0"
"x-bili-timestamp:$timestamp"
```

待签名字符串示例：

```Plain-text
x-bili-accesskeyid:xxxx
x-bili-content-md5:fa6837e35b2f591865b288dfd859ce9d
x-bili-signature-method:HMAC-SHA256
x-bili-signature-nonce:ad184c09-095f-91c3-0849-230dd3744045
x-bili-signature-version:1.0
x-bili-timestamp:1624594467
```



##### 2.生成签名

对步骤1中得到的字符串，使用app_secret进行HMAC-SHA256算法进行签名。

将最后签名得到的字符串添加到Header的`Authorization`字段中