// Static prefix policies for gateway surfaces that have no OpenAPI spec
// (UI bundles). Longest matching prefix wins; consulted only when no
// module auth-policy route template matches the request.
//
// These are REAL Cedar policies, evaluated in the same edge PDP as the
// generated module policies, so each permit MUST be resource-scoped
// (resource == Labs64IO::ApiOperation::"static::<id>") and MUST gate on
// scopes via a `when` clause. An unconstrained/unconditional permit would
// match every request and allow-all the entire gateway. The @pathPrefix /
// @public / @scopes annotations are the routing metadata policy_store reads;
// the permit head + `when` clause are what actually decide.

@id("static::checkout-ui")
@pathPrefix("/checkout-ui")
@public("false")
@tenantRequired("false")
@scopes("admin-role,ecommerce-role")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"static::checkout-ui"
) when { context.scopes.contains("admin-role") || context.scopes.contains("ecommerce-role") };

@id("static::customer-portal-ui")
@pathPrefix("/customer-portal-ui")
@public("false")
@tenantRequired("false")
@scopes("admin-role,default-roles-labs64io")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"static::customer-portal-ui"
) when { context.scopes.contains("admin-role") || context.scopes.contains("default-roles-labs64io") };

// A public prefix needs no scope condition, but still MUST be resource-scoped:
// @id("static::public-prefix")
// @pathPrefix("/some-public-prefix")
// @public("true")
// @tenantRequired("false")
// @scopes("")
// permit(
//   principal,
//   action == Labs64IO::Action::"invoke",
//   resource == Labs64IO::ApiOperation::"static::public-prefix"
// );
