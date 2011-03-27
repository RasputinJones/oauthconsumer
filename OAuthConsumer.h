//
//  OAuthConsumer.h
//  OAuthConsumer
//
//  Created by Jon Crosby on 10/19/07.
//  Copyright 2007 Kaboomerang LLC. All rights reserved.
//
//  Modified by Ugo Enyioha on 03/26/2011
//  Copyright 2010 Avient-Ivy. All rights reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import <Foundation/Foundation.h>
#import "OAProblem.h"
#import "OAToken.h"
#import "OATokenManager.h"
#import "OAConsumer.h"
#import "OAMutableURLRequest.h"
#import "NSString+URLEncoding.h"
#import "NSMutableURLRequest+Parameters.h"
#import "NSURL+Base.h"
#import "OASignatureProviding.h"
#import "OAHMAC_SHA1SignatureProvider.h"
#import "OAPlaintextSignatureProvider.h"
#import "OARequestParameter.h"
#import "OAServiceTicket.h"
#import "OADataFetcher.h"

typedef enum {
    kOAuthRequestMethodGET,
    kOAuthRequestMethodPOST,
} OAuthRequestMethod;

@protocol OAuthDataSource <NSObject>
@required
-(NSString *) appProviderName;
-(NSString *) appPrefix;
-(OAuthAuthHeaderLocation) authHeaderLocation;
-(NSString *) authURL;
-(NSString *) requestTokenURL;
-(NSString *) accessTokenURL;

@optional
-(NSString *) realm;
-(id<OASignatureProviding, NSObject>)signatureProvider;
@end

@protocol OAuthSessionDelegate <NSObject>

@required
-(void) loginDidSucceed;
-(void) loginDidFailWithError:(NSError *) error;

@optional
-(void) shouldModifyAuthenticationRequest:(OAMutableURLRequest *)request;
-(void) shouldModifyAuthorizationRequest:(OAMutableURLRequest *)request;
- (void) apiResponse:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data;
- (void) apiResponse:(OAServiceTicket *)ticket didFailWithError:(NSError *)error;

@end

@interface OAuthConsumer : NSObject {
    
}

- (BOOL)isSessionValid;
- (id)initWithKey:(NSString *)key secret:(NSString *)secret dataSource:(id <OAuthDataSource>) dataSource;
-(void)loginWithHTTPRequestMethod:(OAuthRequestMethod)method params:(NSDictionary *)params delegate:(id<OAuthSessionDelegate>) delegate;
-(void)invokeAPIWithHttpRequestMethod:(OAuthRequestMethod) requestMethod atAPIEndPoint:(NSString *) apiEndpoint withParams:(NSDictionary *)params;
-(BOOL)handleOpenUrl:(NSURL *) url;

@end