//
//  OAuth.m
//  oauthTwitterApp
//
//  Created by Ugo Enyioha on 3/24/11.
//  Copyright 2011 Avient-Ivy. All rights reserved.
//

#import "OAuthConsumer.h"

@interface OAuthConsumer (/* private */)

@property (nonatomic, retain, readwrite) OAConsumer *_consumer;
@property (nonatomic, retain, readwrite) OAToken *_accessToken;
@property (nonatomic, retain, readwrite) id<OAuthDataSource> _dataSource;
@property (nonatomic, assign, readwrite) id<OAuthSessionDelegate> _loginDelegate;
@property (nonatomic, assign, readwrite) OADataFetcher *_fetcher;

@end

@implementation OAuthConsumer

@synthesize _consumer, _accessToken, _dataSource, _loginDelegate, _fetcher;

- (id)initWithKey:(NSString *)key secret:(NSString *)secret dataSource:(id <OAuthDataSource>) dataSource {
    self = [super init];
    if (self) {
        self._dataSource = dataSource;
        _consumer = [[OAConsumer alloc] initWithKey:key secret:secret];
        _accessToken = [[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:[_dataSource appProviderName] 
                                                                              prefix:[_dataSource appPrefix]];
        _fetcher = [[OADataFetcher alloc] init];
    }
    return self;
}

- (void)dealloc {
    [_dataSource release];
    [_accessToken release];
    [_consumer release];
    [_fetcher cancelRequest];
    [_fetcher release];
    [super dealloc];
}

- (BOOL) isSessionValid
{
    return (_accessToken != nil);
}

-(void)loginWithHTTPRequestMethod:(OAuthRequestMethod)method params:(NSDictionary *)params delegate:(id<OAuthSessionDelegate>) delegate
{
    OAMutableURLRequest *request;
    
    _loginDelegate = delegate;
    
    // if the access token is non nil then we have a previously
    // saved access token we can use. Since this is OAuth 1.0
    // the token has an indefinite duration so we do not use 
    // [_accessToken hasExpired]
    // TODO: We'll need to incorp OAuth 2.0 support in order to fold in facebook support
    if ([self isSessionValid]) {
        [_loginDelegate loginDidSucceed];
        return;
    }
    
    NSString *requestTokenURL = [_dataSource requestTokenURL];
    OAuthAuthHeaderLocation authHeaderLocation = [_dataSource authHeaderLocation];
    
    NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
    id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
    
    request = [[[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:requestTokenURL] 
                                      consumer:_consumer 
                                         token:nil 
                                         realm:realm
                             signatureProvider:signatureProvider 
                            authHeaderLocation:authHeaderLocation] autorelease];
    
    NSString *requestM;
    
    switch (method) {
        case kOAuthRequestMethodGET:
            requestM = @"GET";
            break;
            
        case kOAuthRequestMethodPOST:
            requestM = @"POST";
            break;
    }
    
    [request setHTTPMethod:requestM];
    
    __block NSMutableArray *tmpArray = [NSMutableArray arrayWithCapacity:[params count]];
    
    [params enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop){
        OARequestParameter *param = [[OARequestParameter alloc] initWithName:key value:obj];
        [tmpArray addObject:param];
        [param release];
    }];
    
    [request setParameters:tmpArray];
    
    if ([_loginDelegate respondsToSelector:@selector(shouldModifyAuthenticationRequest:)])  {
        [_loginDelegate shouldModifyAuthenticationRequest:request];
    }
    
    [_fetcher fetchDataWithRequest:request delegate:self 
                didFinishSelector:@selector(requestTokenTicket:didFinishWithData:) 
                  didFailSelector:@selector(requestTokenDidFailWithError:)];
}

- (void)requestTokenTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
    
    if (ticket.didSucceed) {
        OAMutableURLRequest *request;
        NSString *responseBody = [[NSString alloc] initWithData:data
                                                       encoding:NSUTF8StringEncoding];
        
        if (_accessToken != nil) {
            [_accessToken release];
            _accessToken = nil;
        }
        
        _accessToken = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
        [responseBody release];
        
        NSString *authURL = [_dataSource authURL];
        OAuthAuthHeaderLocation authHeaderLocation = [_dataSource authHeaderLocation];
        
        NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
        id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
        
        request = [[[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:authURL]
                                                   consumer:_consumer
                                                      token:_accessToken
                                                      realm:realm
                                          signatureProvider:signatureProvider
                                         authHeaderLocation:authHeaderLocation] autorelease];
        
        [request prepare];
        
        [[UIApplication sharedApplication] openURL:[request URL]];
    }
}

- (void)requestTokenTicket:(OAServiceTicket *)ticket didFailWithError:(NSError *)error {
    // NSLog(@"%@", error);
    if ([_loginDelegate respondsToSelector:@selector(loginDidFailWithError:)]){
        [_loginDelegate loginDidFailWithError:error];
    }
}

- (void)successfulAuthorizationWithPin:(NSString *)pin {
    // NSLog(@"successfulAuthorizationWithPin:%@", pin);
    OAMutableURLRequest *request;
    
    NSString *accessTokenURL = [_dataSource accessTokenURL];
    OAuthAuthHeaderLocation authHeaderLocation = [_dataSource authHeaderLocation];
    
    NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
    id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
    
    request = [[[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:accessTokenURL]
                                               consumer:_consumer
                                                  token:_accessToken
                                                  realm:realm
                                      signatureProvider:signatureProvider
                                     authHeaderLocation:authHeaderLocation] autorelease];
    
    OARequestParameter *p1 = [[OARequestParameter alloc] initWithName:@"oauth_verifier"
                                                                value:pin];
    NSArray *params = [NSArray arrayWithObject:p1];
    [request setParameters:params];
    [p1 release];
    
    if ([_loginDelegate respondsToSelector:@selector(shouldModifyAuthorizationRequest:)])  {
        [_loginDelegate shouldModifyAuthorizationRequest:request];
    }
    
    [_fetcher fetchDataWithRequest:request
                         delegate:self
                didFinishSelector:@selector(accessTokenTicket:didFinishWithData:)
                  didFailSelector:@selector(accessTokenTicket:didFailWithError:)];
}

- (void)failedAuthorization {
    // NSLog(@"failedAuthorization");
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:@"Failed Authorization", NSLocalizedDescriptionKey, nil];
    
    if ([_loginDelegate respondsToSelector:@selector(loginDidFailWithError:)]){    
        [_loginDelegate loginDidFailWithError:[NSError errorWithDomain:@"OAuth Error" code:1 userInfo:userInfo]];
    }
}

- (void)accessTokenTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
    if (ticket.didSucceed) {
        // NSLog(@"accessTokenSuccess");
        
        NSString *responseBody = [[NSString alloc] initWithData:data
                                                       encoding:NSUTF8StringEncoding];
        
        if (_accessToken != nil) {
            [_accessToken release];
            _accessToken = nil;
        }
        
        _accessToken = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
        [responseBody release];
        
        [_accessToken storeInUserDefaultsWithServiceProviderName:[_dataSource appProviderName]
                                                              prefix:[_dataSource appPrefix]];
        
        // inform success
        [_loginDelegate loginDidSucceed];
    }
}

- (void)accessTokenTicket:(OAServiceTicket *)ticket didFailWithError:(NSError *)error {
    // NSLog(@"%@", error);
    if ([_loginDelegate respondsToSelector:@selector(loginDidFailWithError:)]){
        [_loginDelegate loginDidFailWithError:error];
    }
}

-(BOOL) handleOpenUrl:(NSURL *) url
{
    if (!url) { 
		return NO; 
	}
	
	NSArray *pairs = [[url query] componentsSeparatedByString:@"&"];
	NSMutableDictionary *response = [NSMutableDictionary dictionary];
	
	for (NSString *item in pairs) {
		NSArray *fields = [item componentsSeparatedByString:@"="];
		NSString *name = [fields objectAtIndex:0];
		NSString *value = [[fields objectAtIndex:1] stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
		
		[response setObject:value forKey:name];
	}
	
    NSString *pin = [response objectForKey:@"oauth_verifier"];
    
    if ([pin length] > 0) {
        // NSLog(@"pin %@", pin);
        [self successfulAuthorizationWithPin:pin];
    }
    else {
        // NSLog(@"no pin");
        [self failedAuthorization];
    }
    
	return YES;
}

-(void)invokeAPIWithHttpRequestMethod:(OAuthRequestMethod) requestMethod atAPIEndPoint:(NSString *) apiEndpoint withParams:(NSDictionary *)params
{
    // NSLog(@"sendButtonAction");
    
    if (_accessToken != nil) {
        OAMutableURLRequest *request;
        
        NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
        id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
        
        request = [[[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:apiEndpoint]
                                                   consumer:_consumer
                                                      token:_accessToken
                                                      realm:realm
                                          signatureProvider:signatureProvider
                                         authHeaderLocation:kOAuthParamsInHttpUriString] autorelease];
        
        NSString *requestM;
        
        switch (requestMethod) {
            case kOAuthRequestMethodGET:
                requestM = @"GET";
                break;
            
            case kOAuthRequestMethodPOST:
                requestM = @"POST";
                break;
        }
        
        [request setHTTPMethod:requestM];
        
        __block NSMutableArray *tmpArray = [NSMutableArray arrayWithCapacity:[params count]];
        
        [params enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop){
            OARequestParameter *param = [[OARequestParameter alloc] initWithName:key value:obj];
            [tmpArray addObject:param];
            [param release];
        }];
        
        [request setParameters:tmpArray];
        
        [_fetcher fetchDataWithRequest:request
                             delegate:self
                    didFinishSelector:@selector(apiResponse:didFinishWithData:)
                      didFailSelector:@selector(apiResponse:didFailWithError:)];
    }
}

- (void) apiResponse:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data
{
    if ([_loginDelegate respondsToSelector:@selector(apiResponse:didFinishWithData:)]) {
        [_loginDelegate apiResponse:ticket didFinishWithData:data];
    }
}

- (void) apiResponse:(OAServiceTicket *)ticket didFailWithError:(NSError *)error
{
    // NSLog(@"%@", error);
    if ([_loginDelegate respondsToSelector:@selector(apiResponse:didFailWithError:)]){
        [_loginDelegate apiResponse:ticket didFailWithError:error];
    }
}

@end
