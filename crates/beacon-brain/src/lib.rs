use anyhow::{anyhow, Result};
use beacon_core::BrainConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct Brain {
    client: Client,
    config: BrainConfig,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
}

#[derive(Serialize, Deserialize, Clone)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub action: String,
    pub subdomain: Option<String>,
    pub domain: Option<String>,
    pub handler: Option<String>,
    pub explanation: String,
}

impl Brain {
    pub fn new(config: BrainConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    pub async fn parse_intent(&self, prompt: &str, sites: &[beacon_core::Site]) -> Result<Intent> {
        let context = if !sites.is_empty() {
            let sites_list: Vec<String> = sites
                .iter()
                .map(|s| format!("  - {} ({})", s.full_domain(), s.handler_type))
                .collect();
            format!("Current sites:\n{}\n", sites_list.join("\n"))
        } else {
            "No sites configured.\n".to_string()
        };

        let system = r#"You are Beacon's AI brain. Parse user requests about web hosting and return JSON.

Actions: add_site, remove_site, list_sites, get_status, help, unknown

Example responses:
{"action":"add_site","subdomain":"blog","domain":"example.com","handler":"proxy","explanation":"Adding blog site"}
{"action":"list_sites","subdomain":null,"domain":null,"handler":null,"explanation":"Listing all sites"}
{"action":"remove_site","subdomain":"test","domain":"example.com","handler":null,"explanation":"Removing test site"}"#;

        let user = format!("{}User: {}", context, prompt);

        let req = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![
                Message {
                    role: "system".into(),
                    content: system.into(),
                },
                Message {
                    role: "user".into(),
                    content: user,
                },
            ],
            temperature: 0.1,
        };

        let resp = self
            .client
            .post(format!("{}/chat/completions", self.config.api_base))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(anyhow!("AI API error: {}", resp.status()));
        }

        let chat: ChatResponse = resp.json().await?;
        let content = chat
            .choices
            .first()
            .map(|c| c.message.content.as_str())
            .ok_or_else(|| anyhow!("No response from AI"))?;

        let intent: Intent = serde_json::from_str(content.trim())
            .map_err(|e| anyhow!("Failed to parse AI response: {}", e))?;

        Ok(intent)
    }

    pub async fn explain(&self, error: &str, context: &str) -> Result<String> {
        let req = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![
                Message {
                    role: "system".into(),
                    content: "Explain errors concisely in under 100 words.".into(),
                },
                Message {
                    role: "user".into(),
                    content: format!("Error: {}\nContext: {}", error, context),
                },
            ],
            temperature: 0.3,
        };

        let resp = self
            .client
            .post(format!("{}/chat/completions", self.config.api_base))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&req)
            .send()
            .await?;

        let chat: ChatResponse = resp.json().await?;
        Ok(chat
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }
}
