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
@property (nonatomic, assign, readwrite) id<OAuthSession> _loginDelegate;

@end

@implementation OAuthConsumer

@synthesize _consumer, _accessToken, _dataSource, _loginDelegate;

- (id)initWithKey:(NSString *)key secret:(NSString *)secret dataSource:(id <OAuthDataSource>) dataSource {
    self = [super init];
    if (self) {
        self._dataSource = dataSource;
        _consumer = [[OAConsumer alloc] initWithKey:key secret:secret];
        _accessToken = [[OAToken alloc] initWithUserDefaultsUsingServiceProviderName:[_dataSource appProviderName] 
                                                                              prefix:[_dataSource appPrefix]];
    }
    return self;
}

- (void)dealloc {
    [_dataSource release];
    [_accessToken release];
    [_consumer release];
    [super dealloc];
}

-(void) login:(id<OAuthSession>) delegate
{
    OAMutableURLRequest *request;
    OADataFetcher *fetcher; 
    
    _loginDelegate = delegate;
    
    NSString *requestTokenURL = [_dataSource requestTokenURL];
    OAuthAuthHeaderLocation authHeaderLocation = [_dataSource authHeaderLocation];
    
    NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
    id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
    
    request = [[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:requestTokenURL] 
                                      consumer:_consumer 
                                         token:nil 
                                         realm:realm
                             signatureProvider:signatureProvider 
                            authHeaderLocation:authHeaderLocation];
    
    if ([_loginDelegate respondsToSelector:@selector(shouldModifyAuthenticationRequest:)])  {
        [_loginDelegate shouldModifyAuthenticationRequest:request];
    }
    
    fetcher = [[[OADataFetcher alloc] init] autorelease];
    [fetcher fetchDataWithRequest:request delegate:self 
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
    NSLog(@"%@", error);
    [_loginDelegate loginDidFailWithError:error];
}

- (void)successfulAuthorizationWithPin:(NSString *)pin {
    NSLog(@"successfulAuthorizationWithPin:%@", pin);
    OAMutableURLRequest *request;
    OADataFetcher *fetcher;
    
    NSString *accessTokenURL = [_dataSource accessTokenURL];
    OAuthAuthHeaderLocation authHeaderLocation = [_dataSource authHeaderLocation];
    
    NSString *realm = [_dataSource respondsToSelector:@selector(realm)] ? [_dataSource realm] : nil;
    id<OASignatureProviding, NSObject> signatureProvider = [_dataSource respondsToSelector:@selector(signatureProvider)] ? [_dataSource signatureProvider] : nil;
    
    request = [[[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:accessTokenURL]
                                               consumer:nil
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
    
    fetcher = [[[OADataFetcher alloc] init] autorelease];
    
    [fetcher fetchDataWithRequest:request
                         delegate:self
                didFinishSelector:@selector(accessTokenTicket:didFinishWithData:)
                  didFailSelector:@selector(accessTokenTicket:didFailWithError:)];
}

- (void)failedAuthorization {
    NSLog(@"failedAuthorization");
    
    NSDictionary *userInfo = [NSDictionary dictionaryWithObjectsAndKeys:@"Failed Authorization", NSLocalizedDescriptionKey, nil];
    
    [_loginDelegate loginDidFailWithError:[NSError errorWithDomain:@"OAuth Error" code:1 userInfo:userInfo]];
}

- (void)accessTokenTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
    if (ticket.didSucceed) {
        NSLog(@"accessTokenSuccess");
        
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
    NSLog(@"%@", error);
    [_loginDelegate loginDidFailWithError:error];
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
        NSLog(@"pin %@", pin);
        [self successfulAuthorizationWithPin:pin];
    }
    else {
        NSLog(@"no pin");
        [self failedAuthorization];
    }
    
	return YES;
}

//- (void)sendButtonAction {
//    NSLog(@"sendButtonAction");
//    
//    if (self.accessToken != nil) {
//        OAMutableURLRequest *request;
//        OADataFetcher *fetcher;
//        
//        request = [[[OAMutableURLRequest alloc] initWithURL:@"http://api.twitter.com/1/statuses/update.json"
//                                                   consumer:self.consumer
//                                                      token:self.accessToken
//                                                      realm:nil
//                                          signatureProvider:nil
//                                         authHeaderLocation:kOAuthParamsInHttpUriString] autorelease];
//        
//        [request setHTTPMethod:@"POST"];
//        
//        OARequestParameter *x1 = [[OARequestParameter alloc] initWithName:@"status" value:self.message.text];
//        
//        NSArray *params = [NSArray arrayWithObjects:x1, nil];
//        [request setParameters:params];
//        
//        
//        fetcher = [[[OADataFetcher alloc] init] autorelease];
//        [fetcher fetchDataWithRequest:request
//                             delegate:self
//                    didFinishSelector:@selector(statusRequestTokenTicket:didFinishWithData:)
//                      didFailSelector:@selector(statusRequestTokenTicket:didFailWithError:)];
//        
//        [x1 release];
//    }
//}
//
//- (void)statusRequestTokenTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data {
//    if (ticket.didSucceed) {
//        NSString *responseBody = [[NSString alloc] initWithData:data
//                                                       encoding:NSUTF8StringEncoding];
//        NSLog(@"%@", responseBody);
//        [responseBody release];
//    }
//}
//
//- (void)statusRequestTokenTicket:(OAServiceTicket *)ticket didFailWithError:(NSError *)error {
//    NSLog(@"%@", error);
//    [_loginDelegate loginDidFailWithError:error];
//}

@end
