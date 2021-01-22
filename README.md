### Third party API
Get token with OAuth2 flow `password` (otherwise `authorization_code`, `implicit`, `client_credentials`)
```shell
curl -v -u some-client:some-client-pass http://localhost:8080/oauth/token
 -d "grant_type=password&username=user&password=password"
```
Access resource
```shell
curl -v localhost:8080/third-party/v1/info
 --header 'Authorization: Bearer <<token>>'
```

### Ordinary API
Access resource with fixed token `javis`
```shell
curl -v http://localhost:8080/user/info
 --header 'Authorization: Bearer javis'
```
