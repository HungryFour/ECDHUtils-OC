//
//  ECkeyUtils.m
//  RSADemo
//
//  Created by 武建明 on 2018/6/20.
//  Copyright © 2018年 Ive. All rights reserved.
//

#import "ECkeyUtils.h"

#import <openssl/pem.h>
#import <openssl/obj_mac.h>
#import <openssl/ecdh.h>

@implementation ECkeyPairs

@end

@implementation ECkeyUtils

typedef enum VoidType {
    VoidTypePrivate  = 0,
    VoidTypePublic
} voidType;

static int KCurveName = NID_secp256k1; //曲线参数,需多端一致

- (ECkeyPairs *)eckeyPairs{
    if (!_eckeyPairs) {
        _eckeyPairs = [[ECkeyPairs alloc] init];
    }
    return _eckeyPairs;
}
- (void)generatekeyPairs{
    // 生成公钥私钥
    EC_KEY *eckey;
    eckey = [self createNewKeyWithCurve:KCurveName];
    NSString  *privatePem = [self getPem:eckey voidType:VoidTypePrivate];
    NSString  *publicPem = [self getPem:eckey voidType:VoidTypePublic];
    self.eckeyPairs.privatePem = privatePem;
    self.eckeyPairs.publicPem = publicPem;
    EC_KEY_free(eckey);
}
+ (NSString *)getShareKeyFromPeerPubPem:(NSString *)peerPubPem
                             privatePem:(NSString *)privatePem
                                 length:(int)length{
    // 根据私钥PEM字符串,生成私钥
    EC_KEY *clientEcKey = [ECkeyUtils privateKeyFromPEM:privatePem];
    if (!length) {
        // 获取私钥长度
        const EC_GROUP *group = EC_KEY_get0_group(clientEcKey);
        length = (EC_GROUP_get_degree(group) + 7)/8;
    }
    NSLog(@"\n--------------------------------------------------------------需生成Sharekey长度:%d",length);
    // 根据peerPubPem生成新的公钥EC_KEY
    EC_KEY *serverEcKey = [ECkeyUtils publicKeyFromPEM:peerPubPem];
    const EC_POINT *serverEcKeyPoint = EC_KEY_get0_public_key(serverEcKey);
    char shareKey[length];
    ECDH_compute_key(shareKey, length, serverEcKeyPoint, clientEcKey,  NULL);
    // 释放公钥,释放私钥
    EC_KEY_free(clientEcKey);
    EC_KEY_free(serverEcKey);

    NSData *shareKeyData = [NSData dataWithBytes:shareKey length:length];
    NSString *shareKeyStr = [shareKeyData base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    NSLog(@"\nShareKey:\n--------\n%@\n--------",shareKeyStr);
    return shareKeyStr;
}

/**
 获取PEM格式的EC_KEY

 @param ecKey 目标EC_KEY
 @param voidType 方法类型
 @return 返回PEM格式的KEY
 */
- (NSString *)getPem:(EC_KEY *)ecKey
            voidType:(voidType)voidType{
    BIO *out = NULL;
    BUF_MEM *buf;
    buf = BUF_MEM_new();
    out = BIO_new(BIO_s_mem());
    switch (voidType) {
        case VoidTypePrivate:
            PEM_write_bio_ECPrivateKey(out, ecKey, NULL, NULL, 0, NULL, NULL);
            break;
        case VoidTypePublic:
            PEM_write_bio_EC_PUBKEY(out, ecKey);
            break;
        default:
            break;
    }
    BIO_get_mem_ptr(out, &buf);
    NSString  *pem = [[NSString alloc] initWithBytes:buf->data
                                              length:(NSUInteger)buf->length
                                            encoding:NSASCIIStringEncoding];
    BIO_free(out);
    return pem;
}

+ (EC_KEY *)publicKeyFromPEM:(NSString *)publicKeyPEM {
    // 将PEM格式的公钥字符串转化成EC_KEY
    const char *buffer = [publicKeyPEM UTF8String];
    BIO *bpubkey = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    EVP_PKEY *public = PEM_read_bio_PUBKEY(bpubkey, NULL, NULL, NULL);
    EC_KEY *ec_cdata = EVP_PKEY_get1_EC_KEY(public);
    BIO_free_all(bpubkey);
    return ec_cdata;
}
+ (EC_KEY *)privateKeyFromPEM:(NSString *)privateKeyPEM {
    // 将PEM格式的私钥字符串转化成EC_KEY
    const char *buffer = [privateKeyPEM UTF8String];
    BIO *out = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    EC_KEY *pricateKey = PEM_read_bio_ECPrivateKey(out, NULL, NULL, NULL);
    BIO_free_all(out);
    return pricateKey;
}
- (EC_KEY *)createNewKeyWithCurve:(int)curve {
    // 生成EC_KEY对象
    int asn1Flag = OPENSSL_EC_NAMED_CURVE;
    int form = POINT_CONVERSION_UNCOMPRESSED;
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    eckey = EC_KEY_new();
    group = EC_GROUP_new_by_curve_name(curve);
    EC_GROUP_set_asn1_flag(group, asn1Flag);
    EC_GROUP_set_point_conversion_form(group, form);
    EC_KEY_set_group(eckey, group);

    int resultFromKeyGen = EC_KEY_generate_key(eckey);
    if (resultFromKeyGen != 1){
        raise(-1);
    }
    return eckey;
}

@end
