//
//  ViewController.m
//  ECDHUtils
//
//  Created by 武建明 on 2018/6/21.
//  Copyright © 2018年 Four_w. All rights reserved.
//

#import "ViewController.h"
#import "ECkeyUtils.h"

@interface ViewController ()

@property (strong, nonatomic) IBOutlet UITextView *logTextView;

@property (strong, nonatomic)ECkeyUtils *aKeyUtils;

@property (strong, nonatomic)ECkeyUtils *bKeyUtils;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}
- (ECkeyUtils *)aKeyUtils{
    if (!_aKeyUtils) {
        _aKeyUtils = [[ECkeyUtils alloc] init];
    }
    return _aKeyUtils;
}
- (ECkeyUtils *)bKeyUtils{
    if (!_bKeyUtils) {
        _bKeyUtils = [[ECkeyUtils alloc] init];
    }
    return _bKeyUtils;
}
- (IBAction)generateAKeypairs {
    /*
     生成A端公钥私钥
     */
    [self.aKeyUtils generatekeyPairs];
    NSString *publicLog = [NSString stringWithFormat:@"A端publicPem__________\n%@",self.aKeyUtils.eckeyPairs.publicPem];
    NSLog(@"%@",publicLog);
    [self addlogText:publicLog];
}
- (IBAction)generateBKeypairs {
    /*
     生成B端公钥私钥
     */
    [self.bKeyUtils generatekeyPairs];
    NSString *publicLog = [NSString stringWithFormat:@"B端publicPem__________\n%@",self.bKeyUtils.eckeyPairs.publicPem];
    NSLog(@"%@",publicLog);
    [self addlogText:publicLog];
}
- (IBAction)generateDHKey {
    /*
     生成协商密钥
     DH(A端私钥+B端公钥) = share_key
     DH(B端私钥+A端公钥) = share_key
     */
    NSString *shareABKey = [ECkeyUtils getShareKeyFromPeerPubPem:self.bKeyUtils.eckeyPairs.publicPem privatePem:self.aKeyUtils.eckeyPairs.privatePem length:32];
    NSString *shareABKeyLog = [NSString stringWithFormat:@"shareKeyA->B__________\n%@",shareABKey];
    NSLog(@"%@",shareABKeyLog);
    [self addlogText:shareABKeyLog];


    NSString *shareBAKey = [ECkeyUtils getShareKeyFromPeerPubPem:self.aKeyUtils.eckeyPairs.publicPem privatePem:self.bKeyUtils.eckeyPairs.privatePem length:32];
    NSString *shareBAKeyLog = [NSString stringWithFormat:@"shareKeyB->A__________\n%@",shareBAKey];
    NSLog(@"%@",shareBAKeyLog);
    [self addlogText:shareBAKeyLog];

}
#pragma mark - help method
- (void)addlogText:(NSString *)text {
    NSString *logText = [NSString stringWithFormat:@"%@\n%@\n",self.logTextView.text,text];
    self.logTextView.text = logText;
    [self scrollsToBottomAnimated:YES];
}
- (void)scrollsToBottomAnimated:(BOOL)animated {
    [self.logTextView scrollRangeToVisible:NSMakeRange(self.logTextView.text.length, 1)];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
