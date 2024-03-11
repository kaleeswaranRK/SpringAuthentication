//package com.springauth.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
//import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
//import org.springframework.web.client.RestTemplate;
//
//@Configuration
//@EnableWebSecurity
//public class OAuthSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    private final ClientRegistrationRepository clientRegistrationRepository;
//    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
//
//    @Autowired
//    public OAuthSecurityConfig(ClientRegistrationRepository clientRegistrationRepository,
//                               OAuth2AuthorizedClientRepository authorizedClientRepository) {
//        this.clientRegistrationRepository = clientRegistrationRepository;
//        this.authorizedClientRepository = authorizedClientRepository;
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.csrf().disable()
//            .authorizeRequests()
//                .antMatchers("/api").authenticated()
//            .and()
//            .oauth2Login()
//                .loginPage("/login") // Custom login page URL
//            .and()
//            .logout()
//                .logoutSuccessUrl("/login?logout") // Redirect URL after logout
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID");
//    }
//
//    @Override
//    @Bean
//    public RestTemplate restTemplate() {
//        OAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
//                clientRegistrationRepository, authorizedClientRepository);
//        OAuth2AuthorizedClientService authorizedClientService = new OAuth2AuthorizedClientService(
//                clientRegistrationRepository, authorizedClientRepository);
//        OAuth2AccessTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
//        authorizedClientManager.setAuthorizedClientProvider(
//                new AuthorizationCodeOAuth2AuthorizedClientProvider(
//                        accessTokenResponseClient));
//        OAuth2AuthorizedClientRepositoryFilter authorizedClientRepositoryFilter =
//                new OAuth2AuthorizedClientRepositoryFilter(authorizedClientManager);
//        RestTemplate restTemplate = new RestTemplate();
//        restTemplate.getInterceptors().add(new ServletOAuth2AuthorizedClientExchangeFilterFunction(
//                authorizedClientManager, authorizedClientRepositoryFilter));
//        return restTemplate;
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//}
