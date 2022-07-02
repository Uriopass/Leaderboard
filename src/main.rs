mod db;
mod migrate;

use crate::db::Database;
use axum::extract::Path;
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use axum_client_ip::ClientIp;
use include_dir::{include_dir, Dir};
use r2d2_sqlite::rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

pub static MIGRATIONS: Dir = include_dir!("migrations");

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut path = "db.db";
    if std::fs::metadata(path)
        .map(|x| !x.is_file())
        .unwrap_or(true)
        && std::fs::metadata("storage")
            .map(|x| x.is_dir())
            .unwrap_or(false)
    {
        tracing::info!("no db file found but a storage directory, going to put the db there.");
        path = "storage/db.db";
    }
    let db = Database::new(path).expect("could not open db");

    tracing::info!(
        "sqlite version: {}",
        db.connection()
            .unwrap()
            .query_row("select sqlite_version();", [], |v| v
                .get::<usize, String>(0))
            .unwrap()
    );

    let app = create_router(db);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|x| x.parse().ok())
        .unwrap_or(80);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

fn create_router(db: Extension<Database>) -> Router {
    migrate::migrate(&db.0, &MIGRATIONS).expect("could not run migrations");

    let cors = CorsLayer::new()
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .allow_origin(tower_http::cors::Any);

    Router::new()
        .route("/api/score", post(create_score))
        .route("/api/score/:game", get(get_scores))
        .layer(db)
        .layer(cors)
}

/// create_score is a handler for the POST /api/score endpoint.
async fn create_score(
    Json(mut payload): Json<CreateScore>,
    Extension(db): Extension<Database>,
    ClientIp(ip): ClientIp,
) -> impl IntoResponse {
    tracing::info!(
        "add score for {}: {} {} {:?}",
        ip,
        payload.score,
        payload.game,
        payload.username
    );
    let client = db.connection().unwrap();

    if payload.game.len() == 0 {
        return StatusCode::BAD_REQUEST;
    }
    if payload
        .username
        .as_ref()
        .map(|x| x.len() == 0)
        .unwrap_or(true)
    {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);

        payload.username = Some(format!("player_{}", hasher.finish()));
    }

    let mut stmt = client
        .prepare_cached(
            r#"
            INSERT INTO scores (game, username, ip, score) VALUES (?1, ?2, ?3, ?4) ON CONFLICT (game, username) DO UPDATE SET score = ?4 WHERE ?4 > score;
        "#,
        )
        .unwrap();
    let rows = stmt
        .execute(params![
            payload.game,
            payload.username,
            ip.to_string(),
            payload.score
        ])
        .unwrap();
    tracing::info!("inserted {} rows", rows);
    StatusCode::CREATED
}

/// get_scores is a handler for the GET /api/score/:game route.
/// It returns a list of the first 10 scores for the given game, sorted by score descending.
async fn get_scores(
    Path(game): Path<String>,
    Extension(db): Extension<Database>,
) -> Json<Vec<GetScore>> {
    tracing::info!("get scores for {}", game);
    let client = db.connection().unwrap();
    let mut stmt = client
        .prepare_cached(
            r#"
            SELECT username, score FROM scores WHERE game = ?1 ORDER BY score DESC LIMIT 10
        "#,
        )
        .unwrap();
    let scores = stmt
        .query_map(params![game], |row| {
            let username = row.get("username")?;
            let score = row.get("score")?;
            Ok(GetScore { username, score })
        })
        .unwrap();
    let scores = scores.collect::<Result<Vec<_>, _>>().unwrap();
    Json(scores)
}

#[derive(Debug, PartialEq, Serialize)]
struct GetScore {
    username: String,
    score: f64,
}

#[derive(Deserialize)]
struct CreateScore {
    game: String,
    username: Option<String>,
    score: f64,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    // Write the tests using an in memory db that tests that the scores
    // are actually stored and can be queried properly. Check that the scores are sorted.
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse, Json};

    // Test inserting a score and getting the scores for a game using the create_score and get_scores endpoints.
    #[tokio::test]
    async fn test_insert() {
        let db = Database::new(":memory:").unwrap();

        migrate::migrate(&db.0, &MIGRATIONS).expect("could not run migrations");

        let resp = create_score(
            Json(CreateScore {
                game: "test".to_string(),
                username: Some("test".to_string()),
                score: 1.0,
            }),
            db.clone(),
            ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = create_score(
            Json(CreateScore {
                game: "test".to_string(),
                username: Some("test".to_string()),
                score: 2.0,
            }),
            db.clone(),
            ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = create_score(
            Json(CreateScore {
                game: "test".to_string(),
                username: Some("test3".to_string()),
                score: 3.0,
            }),
            db.clone(),
            ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = create_score(
            Json(CreateScore {
                game: "test".to_string(),
                username: Some("test3".to_string()),
                score: 1.0,
            }),
            db.clone(),
            ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = create_score(
            Json(CreateScore {
                game: "test".to_string(),
                username: None,
                score: 4.0,
            }),
            db.clone(),
            ClientIp(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let mut resp = get_scores(Path("test".to_string()), db.clone()).await;

        assert!(resp.0[0].username.starts_with("player_"));

        resp.0[0].username = "lol".to_string();

        assert_eq!(
            resp.0,
            vec![
                GetScore {
                    username: "lol".to_string(),
                    score: 4.0,
                },
                GetScore {
                    username: "test3".to_string(),
                    score: 3.0,
                },
                GetScore {
                    username: "test".to_string(),
                    score: 2.0,
                },
            ]
        );
    }
}
