//
//  TwitterDataSource.h
//  oauthTwitterApp
//
//  Created by Ugo Enyioha on 3/25/11.
//  Copyright 2011 Avient-Ivy. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAuthConsumer.h"

@interface TwitterDataSource : NSObject <OAuthDataSource> {
    
}

+(id) dataSource;

@end
