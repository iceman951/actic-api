use actix_web::{post, web, App, HttpResponse, HttpServer, Responder,http::header};
use actix_cors::Cors;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

async fn call_mock_api() -> impl Responder {
    let response = reqwest::get("https://jsonplaceholder.typicode.com/todos/1")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    HttpResponse::Ok().body(response)
}

async fn call_mock_post_api() -> impl Responder {
    let response = reqwest::Client::new()
        .post("https://jsonplaceholder.typicode.com/posts")
        .json(&serde_json::json!({
            "title": "foo",
            "body": "bar",
            "userId": 2
        }))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    HttpResponse::Ok().body(response)
}

#[derive(Debug, Deserialize, Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

#[post("/api/login")]
async fn login(login_request: web::Json<LoginRequest>) -> impl Responder {
    // Mocking the login process
    if login_request.username == "admin" && login_request.password == "password" {
        let secret_key =
            env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY environment variable not set");
        let encoding_key = EncodingKey::from_secret(secret_key.as_bytes());
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // Token expires in 1 hour

        let claims = Claims {
            sub: login_request.username.clone(),
            exp,
        };

        let token = encode(&Header::default(), &claims, &encoding_key)
            .expect("Failed to generate JWT token");

        HttpResponse::Ok().json(LoginResponse { token })
    } else {
        HttpResponse::Unauthorized().body("Invalid username or password")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env::set_var("JWT_SECRET_KEY", "your_secret_key");

    HttpServer::new(|| {

        let cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_origin("http://localhost:5173")
        .allowed_headers(vec![
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::CONTENT_ENCODING,
            header::ACCEPT,
        ])
        .supports_credentials();

        App::new()
            .service(login)
            .route("/mock", web::get().to(call_mock_api))
            .route("/post_mock", web::get().to(call_mock_post_api))
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}
