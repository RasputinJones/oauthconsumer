//
//  YahooDataSource.m
//  oauthTwitterApp
//
//  Created by Ugo Enyioha on 3/25/11.
//  Copyright 2011 Avient-Ivy. All rights reserved.
//

#import "YahooDataSource.h"


@implementation YahooDataSource

+(id) dataSource
{
    return [[[YahooDataSource alloc] init] autorelease];
}

- (id)init {
    self = [super init];
    if (self) {
        
    }
    return self;
}

-(NSString *) appProviderName
{
    return @"appProvider";
}

-(NSString *) appPrefix
{
    return @"YahooApp";
}

-(OAuthAuthHeaderLocation) authHeaderLocation
{
    return kOAuthParamsInHttpUriString;
}

-(NSString *) authURL
{
    return @"https://api.login.yahoo.com/oauth/v2/request_auth";
}

-(NSString *) requestTokenURL
{
    return @"https://api.login.yahoo.com/oauth/v2/get_request_token";
}

-(NSString *) accessTokenURL
{
    return @"https://api.login.yahoo.com/oauth/v2/get_token";
}

-(NSString *) realm
{
    return nil;
}

-(id<OASignatureProviding, NSObject>)signatureProvider
{
    return nil;
}

@end
