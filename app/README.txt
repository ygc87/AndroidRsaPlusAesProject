本应用以Android客户端加密提交数据到Java服务端后进行解密为例子。

生成RSA公钥和密钥的方法：
打开openssl文件夹下的bin文件夹，执行openssl.exe文件

1.生成 RSA 私钥，出现如下提示说明生成成功
genrsa -out rsa_private_key.pem 1024 ​​

OpenSSL> genrsa -out rsa_private_key.pem 1024
Generating RSA private key, 1024 bit long modulus (2 primes)
....+++++
.....+++++
e is 65537 (0x010001)

2.生成 RSA 公钥
rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem ​​

OpenSSL> rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
writing RSA key


Android端的加密思路需要4步：
1.生成AES密钥；
2.使用RSA公钥加密刚刚生成的AES密钥；
3.再使用第1步生成的AES密钥，通过AES加密需要提交给服务端的数据；
4.将第2与第3生成的内容传给服务端。
 

JAVA服务端的解密思路只需3步：
1.获取到客户端传过来的AES密钥密文和内容密文；
2.使用RSA私钥解密从客户端拿到的AES密钥密文；
3.再使用第2步解密出来的明文密钥，通过AES解密内容的密文。

#package com.jesse.lucifer.androidrsaplusaes.encrypt;包下AES.java类
AES的代码可以在JAVA和Android上通用：

#package com.jesse.lucifer.androidrsaplusaes.encrypt;包下RSA.java类
Android - RSA实现

#package com.jesse.lucifer.androidrsaplusaes.encrypt;包下RSAForJava.java类
JAVA - RSA实现


JAVA的RSA跟Android的RSA有所不同：
1.加载key的时候，JAVA上用的是BASE64Decoder
BASE64Decoder base64Decoder = new BASE64Decoder();
byte[] buffer = base64Decoder.decodeBuffer(publicKeyStr);

而Android上用的Base64，这个地方只是API不一样，作用是一样的
byte[] buffer = Base64.decode(publicKeyStr, Base64.DEFAULT);

2.在JAVA平台上调用Cipher.getInstance()的时候，需要多传一个参数，也就是BouncyCastleProvider的实例：
Cipher cipher = Cipher.getInstance("RSA",new BouncyCastleProvider());
这个类jdk上是没有的，所以需要添加一个jar包bcprov-jdk15-143.jar
如果不这样做，JAVA上解密的时候就会抛出一个BadPaddingException

Exception in thread "main" javax.crypto.BadPaddingException: Blocktype mismatch: 0
	at sun.security.rsa.RSAPadding.unpadV15(RSAPadding.java:332)
	at sun.security.rsa.RSAPadding.unpad(RSAPadding.java:272)
	at com.sun.crypto.provider.RSACipher.doFinal(RSACipher.java:356)
	at com.sun.crypto.provider.RSACipher.engineDoFinal(RSACipher.java:382)
	at javax.crypto.Cipher.doFinal(Cipher.java:2087)
	at com.dyhdyh.encrypt.RSA.decryptByPrivateKey(RSA.java:255)
	at com.dyhdyh.encrypt.RSA.decryptByPrivateKey(RSA.java:238)

这是因为Android的加密标准与JAVA的加密标准不一致导致，Android上的RSA实现是"RSA/None/NoPadding"，
而标准JDK实现是"RSA/None/PKCS1Padding"，这造成了在Android上加密后无法在服务器上解密。

Android上加密
1.将openssl生成出来的公钥，放入assets文件夹内（不一定要放这里，只要能拿到文件内容就行）。

2.加载放在assets文件里的公钥
//加载RSA公钥
RSAPublicKey rsaPublicKey = RSA.loadPublicKey(getAssets().open("rsa_public_key.pem"));

3.再生成一个AES的密钥，用于AES加密
//生成一个AES密钥
String aesKey=AES.generateKeyString();

4.通过RSA的公钥来加密刚刚生成的AES密钥
//用RSA公钥加密AES的密钥
String encryptAesKey = RSA.encryptByPublicKey(aesKey, rsaPublicKey);

5.最后使用AES来加密需要传输的数据，AES加密需要传入两个参数，第一个是明文数据，第二个是3步生成出来的密钥
//再使用AES加密内容，传给服务器
String encryptContent = AES.encrypt(content, aesKey);

6.第5步返回的字符串就是加密过后的数据，最后将4和5传给服务端，接下来就是服务端的事情了。



JAVA解密
1.加载RSA私钥(这里的私钥是跟客户端的公钥是成对的)
//加载私钥
RSAPrivateKey privateKey = RSA.loadPrivateKey(new FileInputStream("G:/RSA密钥/pkcs8_rsa_private_key.pem"));

2.通过RSA的私钥解密客户端传来的AES-KEY（也就是客户端的第4），因为这个key是加过密的，所以我们需要先将key解密成明文
//解密AES-KEY
String decryptAesKey = RSA.decryptByPrivateKey(aesKey, privateKey);

3.AES-KEY加密成明文之后，现在可以拿这个key来解密客户端传过来的数据了
//AES解密数据
String decrypt = AES.decrypt(content, decryptAesKey);