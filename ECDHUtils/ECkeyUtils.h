//
//  ECkeyUtils.h
//  RSADemo
//
//  Created by 武建明 on 2018/6/20.
//  Copyright © 2018年 Ive. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ECkeyPairs : NSObject

/**
 私钥PEM
 */
@property (strong, nonatomic) NSString *privatePem;

/**
 公钥PEM
 */
@property (strong, nonatomic) NSString *publicPem;

/**
 三方公钥
 */
@property (strong, nonatomic) NSString *peerPublicPem;

/**
 生成的协商密钥
 */
@property (strong, nonatomic) NSString *shareKey;

@end

@interface ECkeyUtils : NSObject

@property (strong, nonatomic)ECkeyPairs *eckeyPairs;

/**
 生成ECC(椭圆曲线加密算法)的私钥和公钥
 */
- (void)generatekeyPairs;

/**
 根据三方公钥和自持有的私钥经过DH(Diffie-Hellman)算法生成的协商密钥

 @param peerPubPem 三方公钥
 @param privatePem 自持有私钥
 @param length 协商密钥长度
 @return 协商密钥
 */
+ (NSString *)getShareKeyFromPeerPubPem:(NSString *)peerPubPem
                             privatePem:(NSString *)privatePem
                                 length:(int)length;

@end
