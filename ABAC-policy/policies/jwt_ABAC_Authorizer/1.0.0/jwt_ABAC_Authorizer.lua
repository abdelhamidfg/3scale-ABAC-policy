local _M = require('apicast.policy').new('jwt_ABAC_Authorizer', '1.0.0')
local new = _M.new

function _M.new(configuration)
  local self = new()
  local ops = {}
  local config = configuration or {}
  self.ops = ops
  self.author_rest_endpoint=config.author_rest_endpoint
  self.JWT_claim_name=config.JWT_claim_name
  self.error_message=config.error_message
   return self
end

local function isempty(s)
  return s == nil or s == ''
end

local function check_authorization(auth_endpoint,role,method,resource)
      local is_authorized=false
      if isempty(auth_endpoint) or isempty(role) or isempty(method) or isempty(resource) then
       return is_authorized
      end
      local ops = {}
      local query={}
      query.role=role
      query.method=method
      query.resource=resource
      local httpc = require("resty.http").new()
      local res, err = httpc:request_uri(auth_endpoint, {
        method = "GET",
        body = "",
        query=query,
        headers = {
            ["Content-Type"] = "application/json",
        },
      })
if not res then
    ngx.log(ngx.ERR, "authorization service request failed: ", err)
    return is_authorized 
end
  if res then
      ngx.log(ngx.ERR, "authprization service request success: ", res.body)
      if not isempty(res.body) and string.find(res.body, "true") then
          return true
      end
  end      
      return is_authorized
end

local function deny_request(error_msg)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.say(error_msg)
  ngx.exit(ngx.status)
end

function _M:content(context)
  local data= ngx.req.get_body_data()
  ngx.log(ngx.ERR, "body data= ", data)
  
end
function _M:body_filter()
  -- can read and change response body
  -- https://github.com/openresty/lua-nginx-module/blob/master/README.markdown#body_filter_by_lua
  ngx.log(ngx.ERR, "body filter has been started")
  local resp_body = string.sub(ngx.arg[1], 1, 1000)
       -- ngx.ctx.buffered = (ngx.ctx.buffered or "") .. resp_body
        --if ngx.arg[2] then
         -- ngx.var.resp_body = ngx.ctx.buffered
       -- end
  ngx.log(ngx.ERR, "response body= ", resp_body)
  ngx.log(ngx.ERR, "ngx.arg[1]= ", ngx.arg[1])
  
  ngx.log(ngx.ERR, "ngx.ctx.buffered= ", ngx.ctx.buffered)
end
function _M:access(context)
 -- ngx.req.read_body()
  -- local data= ngx.req.get_body_data()
  local h= ngx.req.get_headers(0, true)
  ngx.log(ngx.ERR,"auth=", h["HTTP_AUTHORIZATION"])
 
  for k,v in pairs(h) do
 ngx.log(ngx.ERR, "context.jwt= ", k,v)
end
  
  local uri = ngx.var.uri
  local request_method =  ngx.req.get_method()
  local is_auth=check_authorization( self.author_rest_endpoint,context.jwt[self.JWT_claim_name],request_method,uri)
  if  is_auth == false then
   return deny_request(self.error_message)
  end   
end  
return _M
