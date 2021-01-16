# jwt-authentication-spring-security
Basic kotlin JWT authentication with spring security

The idea behind JSON Web Token (JWT) is to provide authentication over a stateless API. 

The token ideally will include an expiration date, user data required to show on frontend side as well as authorization roles.

This could be implemented either as a separated microservice or embebed as part of an application.

![how jwt works](./how%20jwt%20works.png)

## Dependencies
* Kotlin 1.3
* Java 11
* Maven 3.6.1

## Link of interest
* [**JWT**](https://www.baeldung.com/java-json-web-tokens-jjwt)
* [**JWT encoder / decoder**](https://jwt.io/)
* [**JWT RFC**](https://tools.ietf.org/html/rfc7519)
* [**JWT RFC registered claims**](https://tools.ietf.org/html/rfc7519#section-4.1)
* [**Tutorial**](https://www.youtube.com/watch?v=X80nJ5T7YpE&t=0s)

## API
```
GET     /
POST    /authenticate
```