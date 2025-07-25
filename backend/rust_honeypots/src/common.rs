// backend/rust_honeypots/src/common.rs

use reqwest::Client;
use std::net::IpAddr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

// Datenstruktur für den HTTP-Client und Konfiguration
// Muss 'Send + Sync' sein, damit sie sicher über Async-Tasks geteilt werden kann
#[derive(Clone)]
pub struct AppState { // 'pub' damit es von anderen Modulen importiert werden kann
    pub http_client: Client,
    pub supabase_api_url: String,
    pub supabase_service_role_key: String,
    pub python_ai_url: String,
}

// Typedef für den gemeinsam genutzten State
pub type SharedAppState = Arc<AppState>;

// Neue Struktur für GeoIP-Daten
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region_code: Option<String>,
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
    pub isp: Option<String>,
    pub organization: Option<String>,
}

impl Default for GeoLocation {
    fn default() -> Self {
        Self {
            country_code: None,
            country_name: None,
            region_code: None,
            region_name: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            isp: None,
            organization: None,
        }
    }
}

// GeoIP lookup using ip-api.com (free service)
pub async fn lookup_geoip(ip: IpAddr, http_client: &Client) -> GeoLocation {
    // Skip private/local IP addresses
    let is_private = match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_multicast(),
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_multicast() || ipv6.is_unspecified(),
    };
    
    if is_private {
        println!("Skipping GeoIP lookup for private/local IP: {}", ip);
        return GeoLocation::default();
    }

    let url = format!("http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org", ip);
    
    println!("Looking up GeoIP for: {}", ip);
    
    match http_client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                if let Ok(geo_data) = response.json::<serde_json::Value>().await {
                    if geo_data.get("status").and_then(|s| s.as_str()) == Some("success") {
                        let location = GeoLocation {
                            country_code: geo_data.get("countryCode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            country_name: geo_data.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            region_code: geo_data.get("region").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            region_name: geo_data.get("regionName").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            city: geo_data.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            latitude: geo_data.get("lat").and_then(|v| v.as_f64()),
                            longitude: geo_data.get("lon").and_then(|v| v.as_f64()),
                            timezone: geo_data.get("timezone").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            isp: geo_data.get("isp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            organization: geo_data.get("org").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        };
                        println!("GeoIP lookup successful: {:?}", location);
                        return location;
                    } else {
                        println!("GeoIP API returned error status for {}: {:?}", ip, geo_data);
                    }
                } else {
                    println!("Failed to parse GeoIP response as JSON for {}", ip);
                }
            } else {
                println!("GeoIP API request failed with status: {} for {}", response.status(), ip);
            }
        }
        Err(e) => {
            eprintln!("GeoIP lookup failed for {}: {:?}", ip, e);
        }
    }
    
    GeoLocation::default()
}