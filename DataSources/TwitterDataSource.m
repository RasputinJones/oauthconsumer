//
//  TwitterDataSource.m
//  oauthTwitterApp
//
//  Created by Ugo Enyioha on 3/25/11.
//  Copyright 2011 Avient-Ivy. All rights reserved.
//

#import "TwitterDataSource.h"
#import "OAMutableURLRequest.h"

@implementation TwitterDataSource

+(id) dataSource
{
    return [[[TwitterDataSource alloc] init] autorelease];
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
    return @"TwitterApp";
}

-(OAuthAuthHeaderLocation) authHeaderLocation
{
    return kOAuthParamsInHttpUriString;
}

-(NSString *) authURL
{
    return @"https://api.twitter.com/oauth/authorize";
}

-(NSString *) requestTokenURL
{
    return @"https://api.twitter.com/oauth/request_token";
}

-(NSString *) accessTokenURL
{
    return @"https://api.twitter.com/oauth/access_token";
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
