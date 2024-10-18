mod proxy;
mod errors;
mod config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Initialise config
    match config::runtime::initialize() {
        Ok(_) => {
            tracing::info!("Configuration initialized successfully");
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            std::process::exit(1);
        }
    }


    // Create a new proxy
    let server = proxy::LLMProxy::new_proxy()
        .map_err(|e| {
            tracing::error!("Error creating proxy: {:?}", e);
            e
        })?;


    server.run_forever();
}