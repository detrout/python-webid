

#define WEBID_MODULE "webid.authorizer"
#define WEBID_DIRECT_METHOD "__direct_trust"
#define WEBID_TRANSITIVE_METHOD "__transitive_trust"

int trust(const char* auth_uri, const char* san_uri, char* method);
