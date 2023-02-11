## Make cert

```
CAROOT=$(pwd) mkcert -install
CAROOT=$(pwd) mkcert tls.lvh.me

cat tls.lvh.me.pem rootCA.pem > tls.lvh.me.crt
```
