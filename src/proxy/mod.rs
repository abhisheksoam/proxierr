mod response;
mod request_modifiers;
mod https;

use std::collections::HashMap;
use std::sync::Arc;
use std::{fs, io};
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use crate::errors::Errors;
use crate::config;

use async_trait::async_trait;
use http::Version;
use pingora::prelude::*;
use pingora::lb::Backend;
use pingora::proxy;
use pingora::server::configuration::ServerConf;
use pingora::tls::ext;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::info;
use url::Url;


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TenantConfig {
    id: String,
    api_key: String,
    rate_limit: u32,
    allowed_models: Vec<String>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
    host: String,
    port: u16,
    use_tls: bool,
}

#[derive(Debug, Clone)]
pub struct LLMProxy {
    providers: HashMap<String, Provider>,
    // tenants: Arc<RwLock<HashMap<String, TenantConfig>>>,

}

impl LLMProxy {
    pub fn new_proxy() -> Result<Server, Errors> {
        let app_conf = &config::runtime::config();
        // let tenants = Arc::new(RwLock::new(Self::load_tenant_config()?));
        let config = Self::load_providers()?;
        let llm_proxy = LLMProxy {
            providers: config,
            // tenants: None,
        };

        let mut opt = Opt::default();
        // opt.daemon = true;
        if let Some(conf) = &app_conf.pingora.daemon {
            opt.daemon = *conf;
        }

        let mut pingora_server =
            Server::new(Some(opt)).map_err(|e| Errors::PingoraError(format!("{}", e)))?;

        let mut conf = ServerConf::default();
        // conf.threads = 8;

        if let Some(threads) = app_conf.pingora.threads {
            conf.threads = threads;
        }
        // conf.error_log = ;
        if let Some(error_log) = &app_conf.pingora.error_log {
            if !error_log.is_empty() {
                conf.error_log = Some(error_log.clone());
            }
        }
        if let Some(pid_file) = &app_conf.pingora.pid_file {
            if !pid_file.is_empty() {
                conf.pid_file = pid_file.clone();
            }
        }

        if let Some(upstream_keepalive_pool_size) = app_conf.pingora.upstream_keepalive_pool_size {
            conf.upstream_keepalive_pool_size = upstream_keepalive_pool_size;
        }


        pingora_server.configuration = conf.into();
        let mut pingora_svc =
            proxy::http_proxy_service(&pingora_server.configuration, llm_proxy.clone());
        pingora_svc.add_tcp("0.0.0.0:80");
        pingora_server.add_service(pingora_svc);

        tracing::info!("Proxy server started on http://{:?}", app_conf.proxy.http);

        println!("Proxierr..... ");
        println!("----------------");
        println!("Version: 1.0.0");
        println!("Listening on: http://{:?}", app_conf.proxy.http);
        println!("Endpoints: {:?}", llm_proxy.providers.keys());
        println!("----------------");

        pingora_server.bootstrap();
        Ok(pingora_server)
    }

    fn load_providers() -> Result<HashMap<String, Provider>, Errors> {
        let config_str = fs::read_to_string("llm_config.json")
            .map_err(|e| Errors::ConfigError(format!("Failed to read config file: {}", e)))?;
        serde_json::from_str(&config_str)
            .map_err(|e| Errors::ConfigError(format!("Failed to parse config: {}", e)))
    }

    async fn validate_request(&self, session: &Session) -> Result<(), Errors> {
        // Validate API limit, Service plan

        Ok(())
    }

    async fn apply_rate_limit(&self, session: &Session) -> Result<(), Errors> {
        // let key = session.peer_ip().to_string();
        // if self.rate_limiter.check_key(&key).is_err() {
        //     return Err(Errors::RateLimitExceeded);
        // }
        Ok(())
    }

    async fn authenticate(&self, tenant_id: &str, api_key: &str) -> Option<TenantConfig> {
        // TODO: Dummy function

        Some(TenantConfig {
            id: tenant_id.to_string(),
            api_key: "dummy_api_key".to_string(),
            rate_limit: 1000,
            allowed_models: vec!["all".to_string()],
        })
    }

    async fn authorize(&self, tenant: &TenantConfig, model: &str) -> bool {
        //TODO: Just dummy function
        true
    }

    fn load_tenant_config() -> Result<HashMap<String, TenantConfig>, Box<dyn std::error::Error>> {
        //TODO: Load tenant configuration from a file or database

        Ok(HashMap::new())
    }
}

pub struct Context {
    pub backend: Backend,
    pub variables: HashMap<String, String>,
    tenant_id: Option<String>,
    provider: Option<String>,
    tries: usize,

}


#[async_trait]
impl ProxyHttp for LLMProxy {
    type CTX = Context;

    // Setting new context
    fn new_ctx(&self) -> Self::CTX {
        Context {
            backend: Backend::new("127.0.0.1:80").expect("Unable to create backend"),
            variables: HashMap::new(),
            tenant_id: None,
            provider: None,
            tries: 0,
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {

        let addr = ("3.108.146.40", 443);
        let peer = Box::new(HttpPeer::new(addr, true, "3.108.146.40".to_string()));
        Ok(peer)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        if ctx.tries > 0 {
            return e;
        }
        ctx.tries += 1;
        e.set_retry(true);
        e
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {

        let mut res = response::Response::new();
        let mut path = session.req_header().uri.path().to_string();

        let mut host = match session.get_header("host") {
            Some(h) => match h.to_str() {
                Ok(h) => h.to_string(),
                Err(e) => {
                    res.status(400).body_json(json!({
                        "error": "PARSE_ERROR",
                        "message": e.to_string(),
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => "".to_string(),
        };

        println!("path: {}", path);
        println!("host: {}", host);

        let tenant_id = match session.req_header().headers.get("X-Tenant-ID") {
            Some(header_value) => match header_value.to_str() {
                Ok(str_value) => str_value.to_string(),
                Err(e) => {
                    res.status(400).body_json(json!({
                        "error": "INVALID TENANT ID",
                        "message": e.to_string(),
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => {
                res.status(400).body_json(json!({
                        "error": "MISSING HEADER",
                        "message": "Missing header id",
                    }));
                return Ok(res.send(session).await);
            }
        };

        let provider = match session.req_header().headers.get("X-Provider") {
            Some(header_value) => match header_value.to_str() {
                Ok(str_value) => str_value.to_string(),
                Err(e) => {
                    res.status(400).body_json(json!({
                        "error": "INVALID Provider ID",
                        "message": e.to_string(),
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => {
                res.status(400).body_json(json!({
                        "error": "MISSING HEADER",
                        "message": "Missing header id",
                    }));
                return Ok(res.send(session).await);
            }
        };

        let api_key = match session.req_header().headers.get("X-Api-Key") {
            Some(header_value) => match header_value.to_str() {
                Ok(str_value) => str_value.to_string(),
                Err(e) => {
                    res.status(400).body_json(json!({
                        "error": "INVALID API KEY",
                        "message": e.to_string(),
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => {
                res.status(400).body_json(json!({
                        "error": "MISSING HEADER",
                        "message": "Missing header id",
                    }));
                return Ok(res.send(session).await);
            }
        };

        // Get the IP address

        let ip = match session.client_addr() {
            Some(ip) => match ip.as_inet() {
                Some(ip) => ip.ip().to_string(),
                None => {
                    res.status(400).body_json(json!({
                        "error": "PARSE_ERROR",
                        "message": "Unable to parse client IP",
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => {
                res.status(400).body_json(json!({
                    "error": "CLIENT_ERROR",
                    "message": "Unable to get client IP",
                }));
                return Ok(res.send(session).await);
            }
        };

        ctx.variables.insert("CLIENT_IP".to_string(), ip.clone());

        // x-real-ip
        let ip = match session.get_header("x-real-ip") {
            Some(h) => match h.to_str() {
                Ok(h) => format!("{}-{}", ip, h),
                Err(e) => {
                    res.status(400).body_json(json!({
                        "error": "PARSE_ERROR",
                        "message": e.to_string(),
                    }));
                    return Ok(res.send(session).await);
                }
            },
            None => ip,
        };


        // Set context
        ctx.tenant_id = Some(tenant_id.clone());
        ctx.provider = Some(provider.to_string().clone());

        let selection_key = format!("{}:{}", ip, path);


        // Log request
        tracing::info!(
            "Request: tenant={}, provider={}, path={}",
            tenant_id,
            provider,
            session.req_header().uri.path()
        );


        // Authenticate
        let tenant_config = match self.authenticate(&tenant_id, &api_key).await {
            Some(config) => config,
            None => {
                res.status(401).body_json(json!({
                    "error": "AUTHENTICATION_FAILED",
                    "message": "Invalid tenant ID",
                }));
                return Ok(res.send(session).await);
            }
        };

        // Authorize
        if !self.authorize(&tenant_config, &provider).await {
            res.status(403).body_json(json!({
                "error": "AUTHORIZATION_FAILED",
                "message": "Tenant is not authorized to use this provider",
            }));
            return Ok(res.send(session).await);
        }

        Ok(false)
    }
}