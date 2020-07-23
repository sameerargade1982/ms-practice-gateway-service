package com.argade.gatewayservice.filters;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class TrackingFilter extends ZuulFilter{
    private static final Logger logger = LoggerFactory.getLogger(TrackingFilter.class);

    private static final int      FILTER_ORDER =  1;
    private static final boolean  SHOULD_FILTER=true;

    @Autowired
    FilterUtils filterUtils;
    private final OAuth2AuthorizedClientService clientService;
    
    TrackingFilter(OAuth2AuthorizedClientService clientService){
    	this.clientService = clientService;
    }
    @Override
    public String filterType() {
        return FilterUtils.PRE_FILTER_TYPE;
    }

    @Override
    public int filterOrder() {
        return FILTER_ORDER;
    }

    public boolean shouldFilter() {
        return SHOULD_FILTER;
    }

    private boolean isCorrelationIdPresent(){
      if (filterUtils.getCorrelationId() !=null){
          return true;
      }

      return false;
    }

    private String generateCorrelationId(){
        return java.util.UUID.randomUUID().toString();
    }

    public Object run() {

        if (isCorrelationIdPresent()) {
            logger.debug("tmx-correlation-id found in tracking filter: {}. ", filterUtils.getCorrelationId());
        }
        else{
            filterUtils.setCorrelationId(generateCorrelationId());
            logger.debug("tmx-correlation-id generated in tracking filter: {}.", filterUtils.getCorrelationId());
        }

        RequestContext ctx = RequestContext.getCurrentContext();
        Optional<String> authorizationHeader = getAuthorizationHeader();
        logger.debug("authorization header from Tracking Filter",authorizationHeader.get() );
        authorizationHeader.ifPresent(s -> ctx.addZuulRequestHeader("Authorization", s));
        logger.debug(String.format("Processing incoming request for {}.",  ctx.getRequest().getRequestURI()));
        return null;
    }
    private Optional<String> getAuthorizationHeader() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                oauthToken.getName());

        OAuth2AccessToken accessToken = client.getAccessToken();

        if (accessToken == null) {
            return Optional.empty();
        } else {
            String tokenType = accessToken.getTokenType().getValue();
            String authorizationHeaderValue = String.format("%s %s", tokenType, accessToken.getTokenValue());
          logger.info(authorizationHeaderValue);
            return Optional.of(authorizationHeaderValue);
        }
    }
}