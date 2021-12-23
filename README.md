# iOS ble蓝牙加密传输
- [iOS ble蓝牙加密传输](#ios-ble蓝牙加密传输)
      - [1、流程图](#1流程图)
      - [2、流程](#2流程)
        - [2.1 发现服务和特征](#21-发现服务和特征)
        - [2.2 ECDH（secp192k1）秘钥协商](#22-ecdhsecp192k1秘钥协商)
        - [2.3 AES加解密](#23-aes加解密)
#### 1、流程图
![图片](https://user-images.githubusercontent.com/20941758/140888056-571f6c99-c020-4c54-973a-0a3bb27394fe.png)
#### 2、流程
`为了区分数据是密钥交换还是解密数据，在数据前增加数据类型和长度；`<br>
|         类型（一个字符）  | 长度（2个字符）  | 数据内容
|   ----  | ----  |----  |
| 0x10 (APP发送自己的公钥给设备)  |  |
| 0x11 (设备发送自己的公钥给APP)  |  |
| 0x20 (APP发送给设备的加密数据)  |  |
| 0x21 (设备发送给APP的加密数据)  |  |
##### 2.1 发现服务和特征
连接上蓝牙后，SDK执行发现设备服务→发现服务下特征操作。其中包含了两个服务：F100和F200。配网SDK在发现服务的时候需要进行判断，如果发现的服务中包含了F200的服务，则SDK需要执行加密流程。<br> 
非加密service：F100，此服务有两个特征characteristic：写特征F101、读特征F102<br> 
加密service：F200，此服务有两个特征characteristic：写特征F201、读特征F202
```Objective-C
//1、扫描ble蓝牙
//发现外设回调
-(void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral advertisementData:(NSDictionary<NSString *,id> *)advertisementData RSSI:(NSNumber *)RSSI;

//2、连接外设
//连接成功回调
-(void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral;

//连接失败回调
-(void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error;

//断开连接回调
-(void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(NSError *)error;

//3、连接成功后发现去发现服务
//发现服务回调
-(void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error;

//4、发现服务的特征
//发现特征回调
-(void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(nonnull CBService *)service error:(nullable NSError *)error;

//5、发送数据
//数据写入成功回调
-(void)peripheral:(CBPeripheral *)peripheral didWriteValueForCharacteristic:(CBCharacteristic *)characteristic error:(NSError *)error;
```
##### 2.2 ECDH（secp192k1）秘钥协商
两端均使用ECDH的方式生成秘钥对，在分别拿到对方的公钥时，再跟自己生成的私钥去进行秘钥协商，得到一个24位的协商结果，也就是AES加解密需要用到的加密key。<br> 
iOS配网SDK通过使用第三方库`GMObjC`完成秘钥协商，具体代码如下：<br> 
`使用GMObjC库生成的公钥在前面补04为49位，私钥在前面补了0000000000000000为32位，故在发送客户端公钥给设备时需要去掉补的04，拿到设备发过来的公钥时需要补上04再进行秘钥协商`<br> 
```Objective-C
#import "GMObjC/GMObjC.h"
 
//设置ECDH椭圆曲线类型为secp192k1
[GMSm2Utils setEllipticCurveType:711];
 
//获取秘钥对
NSArray *clientKey = [GMSm2Utils createKeyPair];
 
//49位公钥
self.clientPublicKey = [clientKey[0] stringByReplacingOccurrencesOfString:@" " withString:@""];
//32位私钥
self.clientPrivateKey = [clientKey[1] stringByReplacingOccurrencesOfString:@" " withString:@""];
 
//去掉04，拼接类型+长度，得到需要发送给设备的公钥数据
NSString *resultPublicKey = [NSString stringWithFormat:@"100030%@",[self.clientPublicKey substringFromIndex:2]];
 
//拿到设备发送过来的公钥后，再结合SDK自己生成的私钥进行秘钥协商，得到加密Key
self.aesKey = [GMSm2Utils computeECDH:[NSString stringWithFormat:@"04%@",[dataStr substringFromIndex:6]] privateKey:self.clientPrivateKey];
```
##### 2.3 AES加解密
`AES加解密通过采用：CBC+nopadding+iv偏移量"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"来进行实现（加密数据必须为16位的倍数，由于采用的是nopadding，故进行补0操作）`<br>
```Objective-C
#define IVKEY @"00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
 
 
//加密
+ (NSString *)aes128EncryptWithContent:(NSString *)plaintext key:(NSString *)key {
     
    NSData *keyData = [[self class] convertHexStrToData:key];
    Byte *keyByte = (Byte *)[keyData bytes];
  
    NSData *ivData = [[self class] convertHexStrToData:IVKEY];
    Byte *ivByte = (Byte *)[ivData bytes];
  
    NSData* data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
     
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    int newSize = 0;
     
    if(diff > 0)
    {
        newSize = (int)dataLength + diff;
    }
     
    char dataPtr[newSize];
    memcpy(dataPtr, [data bytes], [data length]);
    for(int i = 0; i < diff; i++)
    {
        dataPtr[i + dataLength] = 0x00;
    }
     
    size_t bufferSize = newSize + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    memset(buffer, 0, bufferSize);
     
    size_t numBytesCrypted = 0;
     
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x0000, //No padding
                                          keyByte,
                                          kCCKeySizeAES192, //由于得到的加密key为24位，故此处需要设置为kCCKeySizeAES192
                                          ivByte,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
     
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[self class] convertDataToHexStr:resultData];
    }
    free(buffer);
    return nil;
}
 
 
//解密
+ (NSString *)aes128DencryptWithContent:(NSString *)ciphertext key:(NSString *)key {
     
    NSData *data1 = [[self class] convertHexStrToData:ciphertext];
    ciphertext = [TCLGTMBase64 stringByEncodingData:data1];
     
    NSData *keyData = [[self class] convertHexStrToData:key];
    Byte *keyByte = (Byte *)[keyData bytes];
     
    NSData *ivData = [[self class] convertHexStrToData:IVKEY];
    Byte *ivByte = (Byte *)[ivData bytes];
     
    NSData *data = [TCLGTMBase64 decodeData:[ciphertext dataUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
     
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000, //No padding
                                          keyByte,
                                          kCCKeySizeAES192, //由于得到的加密key为24位，故此处需要设置为kCCKeySizeAES192
                                          ivByte,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}
 
/**
 十六进制字符串转化为data
  
 @param str 十六进制字符串
 @return data
 */
+ (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
     
    str = [str stringByReplacingOccurrencesOfString:@" " withString:@""];
     
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
         
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
         
        range.location += range.length;
        range.length = 2;
    }
 
    return hexData;
}
 
/**
 data转换为十六进制字符串
  
 @param data data数据
 @return 十进制字符串
 */
+ (NSString *)convertDataToHexStr:(NSData *)data {
    if (!data || [data length] == 0) {
        return @"";
    }
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:[data length]];
     
    [data enumerateByteRangesUsingBlock:^(const void *bytes, NSRange byteRange, BOOL *stop) {
        unsigned char *dataBytes = (unsigned char*)bytes;
        for (NSInteger i = 0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] == 2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
     
    return string;
}
```
