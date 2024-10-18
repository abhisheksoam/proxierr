use reqwest;
use std::error::Error;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_request() -> Result<(), Box<dyn Error>> {
        let proxy_url = "http://localhost:80/v1/chat/completions";
        let client = reqwest::Client::new();

        let body = serde_json::json!({
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "user",
                    "content": "Hello, how are you?"
                }
            ]
        });


        let response = client.post(proxy_url)
            .header("Content-Type", "application/json")
            .header("X-Tenant-ID", "test-tenant")
            .header("X-Provider", "test-provider")
            .header("X-Api-Key", "test-api-key")
            .json(&body)
            .send()
            .await?;
        let status = response.status();


        println!("Status: {}", status);
        println!("Headers: {:#?}", response.headers());


        let body = response.text().await?;
        println!("Body: {}", body);
        assert!(status.is_success());

        Ok(())
    }
}