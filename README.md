# oauth2-authorization-server-with-pkce
Spring OAuth2 Authorization Server + PKCE with Spring Boot 3.2.5 and Java 17

## Note: Go to website to generate PKCE Code Generator
>https://developer.pingidentity.com/en/tools/pkce-code-generator.html
>>Copy Code-Challenge and Code-Challenge-Method value from there to past on param code_challenge, code_challenge_method with endpoint /authorize below

## Start Application
### Hit on /authorize endpoint below on browser
>http://localhost:8080/oauth2/authorize?response_type=code&client_id=public-client&client_secret=secret&scope=openid&redirect_uri=http://127.0.0.1:8081/login/oauth2/code/public-client&code_challenge=fKtFosbDqw_swmnplGY1GVJZSR67_L97Ot-SbO6Z330&code_challenge_method=S256

## Get Access Token
* Get response value of code from endpoint above to past in code, and copy Code-Verifier from PKCE Code Generator past on param code_verifier
>curl --location 'http://localhost:8080/oauth2/token' \
--header 'Cookie: JSESSIONID=414E48478228F82B8FAA652C0A297ABE' \
--form 'code="cIKUnk38AEc9uXN2GlMU4jSr21NWJQ659QuY5zv07eFX7PZo10Qw8nxjfkXpQAe2B4huG9LTeFCSfErPsahpiI8WXSNqSJdWYi4oKsuAH-Fh938KpAHKeT4Mj-27qHoD"' \
--form 'grant_type="authorization_code"' \
--form 'client_id="public-client"' \
--form 'redirect_uri="http://127.0.0.1:8081/login/oauth2/code/public-client"' \
--form 'code_verifier="Fy9YRPp2Ety7RiK9s0SqG6Dend1Nsfrvh1L7aQxCg_2q1AXdGgiUBeaPryP0MwH4JPMsz7mYsLzC62Zana-IC3i16ow9DCZwAkOgjFUZ8I5pRxnkDHJztK6DzMSwtamD"'

## Get Access Token by Refresh Token
* Copy return value of "refresh_token" from Get Access Token to past in param "refresh_token" below
>curl --location 'http://localhost:8080/oauth2/token' \
--header 'Cookie: JSESSIONID=414E48478228F82B8FAA652C0A297ABE' \
--form 'code="TffhIFNKDyqzoR6BR6NQL1w-ndh8rEg2Mik2EJMd7JuXtaoZQeJx0K-AdB2yqPb11WpI8ebuvf4mTDEM99Uvqa6VuIzgGXcHOl0KGmsa3i1waCL2hVWIrt3U7KVK_hrZ"' \
--form 'grant_type="refresh_token"' \
--form 'client_id="public-client"' \
--form 'redirect_uri="http://127.0.0.1:8081/login/oauth2/code/public-client"' \
--form 'code_verifier="Fy9YRPp2Ety7RiK9s0SqG6Dend1Nsfrvh1L7aQxCg_2q1AXdGgiUBeaPryP0MwH4JPMsz7mYsLzC62Zana-IC3i16ow9DCZwAkOgjFUZ8I5pRxnkDHJztK6DzMSwtamD"' \
--form 'refresh_token="UIGje663G42KO2nxtmEI1UdYvaIJ5Nke_-u1JloYxvlNDhbAdinGNxNz714TeVzyVH2vKDaDByyyH5XLh0h5WpZAL56lRTMs8MpK8qvoEKm5KdPSFHIX7G0-rNu96aGC"'
