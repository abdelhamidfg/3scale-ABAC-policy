
## 3scale ABAC Authorization Policy

This Policy allows APICast to determine if access to an API should be granted or denied  based on a defined ABAC (Attribute Based Access Control) rule in external HTTP service.
The policy sends the below query parameters to external ABAC service:-
| parameter  |  Desc | examples  | 
|---|---|---|
|  role |  user role based on JWT claim value | admin,user  |
| method  | HTTP Verb used in the reques  | GET,POST,PUT,..  |
|  resource | resource uri used in the reques  |  /order |   

Example invocation : 
```shell
curl  "https://<ABAC service endpoint>/role=user&action=GET&resource=/order"
  ```
It expects the response from ABAC service to have a boolean flag  with true/false value.Example json response {"isAllowed":true} ,based on the response the traffic will be blocked or allowed.

The policy requires OpenID Connect authentication method in 3scale API Product. 

The repository has 2 folders :-
- ABAC-policy folder contains 3scale custom policy source code and configurations.
- ABAC-Authorization-service folder contains an implementation example of ABAC service/microservice using RedHat serverless function quarkus runtime and Postgresql database.



## High Level Architecture


![alt text](https://github.com/abdelhamidfg/3scale-ABAC-policy/blob/master/ABAC-Architecture.jpg?raw=true)
- After the client is authenticated using any OAuth 2.0 flow ,the client has a valid JWT token.
- JWT token has a claim for the user role ,e.g   "role": "user" generated by OAuth server/keycloak server.
-  The client sends a request to view the orders ,GET : /orders?id-12121 attached JWT token in the header.
- 3scale ABAC policy extracts the claim value of the role , HTTP method used by the client and resource URI.
- 3scale ABAC policy sends HTTP (GET) request passing query parameters(role,method,resource) to ABAC service to evaluate the authorization policy.
- ABAC service  responds with a json message containing the isAllowed boolean result ,e.g. {"isAllowed":true}.
- ABAC service may use database/LDAP/REDIS for storing ABAC rules.
- 3scale ABAC policy will allow or deny the request based on the reponse of ABAC service.

## Policy Installation on OpenShift

1. Update the following lines in openshift.yml with your own envrironment.
	
    - GIT_REPO openshift.yml:L113
    - APICAST_CUSTOM_NAMESPACE openshift.yml:L117

2. Access the current 3scale namespace for your API casts.

   ```shell
   oc project <<3SCALE_NAMESPACE>>
   ```

3. Create the image stream of the apicast.

   ```shell
   oc -n <<3SCALE_NAMESPACE>> import-image amp-apicast-custom:3scale2.8.0 --from=registry.redhat.io/3scale-amp2/apicast-gateway-rhel8:3scale2.8.0 --confirm
   ```

4. To install the build configs on OpenShift you can use provided template:

   ```shell
   oc -n <<3SCALE_NAMESPACE>> new-app -f openshift.yml -o yaml | oc apply -f -
   ```

## Starting the build

1. To start the first build run the following command:

   ```shell
   oc -n <<3SCALE_NAMESPACE>> start-build apicast-new-policy --wait --follow
   ```

2. To start the second build run the following command:

   ```shell
   oc -n <<3SCALE_NAMESPACE>> start-build apicast-custom --wait --follow
   ```

If you didn't change the output image of the second build, you should see the API Casts (stage and production) being redeployed.

Once the redeploys finish the new policy appearing in the list of policies to add.


## Configuring API Product
1. Log into your Admin portal.
2. From the dropdown menu on the top Access your API or Service and click on `Integration` > `Policies`.
3. Then click on the link `Add policy`.
4. Then click on the `JWT ABAC Authorizer`.
5. Move the new policy to before the default **API Cast** policy.
6. Click on the **JWT ABAC Authorizer** again and you should see its properties.
7. provide the configuration parameters as below : 
   - ABAC Authorization Service HTTP Endpoint.
   - JWT Claim name of the user role.
   - Error message to show to the client when traffic is blocked.
8. Once you finish changing the settings, you can click on **Update policy** button and then `Update Policy Chain`.
9. Go to configuration and promote your changes to staging.
![alt text](https://github.com/abdelhamidfg/3scale-ABAC-policy/blob/master/policy-config.jpg?raw=true)

## Implementing ABAC Service
The implementation example of ABAC service using RedHat serverless function quarkus runtime and Postgresql database.
below steps for installing ABAC service after cloning the repositry.
1. create a new openshift project
    $oc new-project abac-service
2. install PostGreSQL database 
   Switch to developer perspective in Openshift web interface 
   Click on Add ..>Database ..>PostgreSQL ..> Click on Instantiate Template
   Provide template oparameter in Instantiate Template page as below screenshot
   ![alt text](https://github.com/abdelhamidfg/3scale-ABAC-policy/blob/master/postgresql.jpg?raw=true)
3. Creating database table 
  Connect to Postgresql pod terminal
  psql -d apidb -U admin 
  Execute import.sql 
  ![alt text](https://github.com/abdelhamidfg/3scale-ABAC-policy/blob/master/db-table.jpg?raw=true)
4. Install OpenShift pre-requisit Servlerless operators following the [documentation](https://docs.openshift.com/container-platform/4.7/serverless/admin_guide/install-serverless-operator.html#next-steps_installing-openshift-serverless)
5.  Deploy a Quarkus Function to OpenShift Serverless
    
    $ cd ABAC-Authorization-service
    $ kn func deploy -r registry_string -n abac-service -v
![alt text](https://github.com/abdelhamidfg/3scale-ABAC-policy/blob/master/ABAC-service.jpg?raw=true)
