// use crate::{
//     db::get_db,
//     error::Result,
//     models::user::{User, UserInput},
// };

// pub async fn create_users_table() -> Result<()> {
//     let query = r#"
//         DEFINE TABLE IF NOT EXISTS users SCHEMALESS PERMISSIONS FULL;

//         DEFINE FIELD IF NOT EXISTS uuid ON TABLE users TYPE string READONLY;
//         DEFINE FIELD IF NOT EXISTS username ON TABLE users TYPE string READONLY;
//         DEFINE FIELD IF NOT EXISTS password ON TABLE users TYPE string;
//         DEFINE FIELD IF NOT EXISTS email ON TABLE users TYPE option<string>;
//         DEFINE FIELD IF NOT EXISTS email_verified ON TABLE users TYPE bool VALUE false;
//         DEFINE FIELD IF NOT EXISTS role ON TABLE users TYPE string;
//         DEFINE FIELD IF NOT EXISTS disabled ON TABLE users TYPE bool VALUE false;
//         DEFINE FIELD IF NOT EXISTS mfa_enabled ON TABLE users TYPE bool VALUE false;
//         DEFINE FIELD IF NOT EXISTS mfa_secret ON TABLE users TYPE option<string>;
//         DEFINE FIELD IF NOT EXISTS created_at ON TABLE users TYPE datetime VALUE time::now()
// READONLY;         DEFINE FIELD IF NOT EXISTS updated_at ON TABLE users TYPE datetime VALUE
// time::now();

//         DEFINE INDEX IF NOT EXISTS unique_uuid ON TABLE users FIELDS uuid UNIQUE;
//         DEFINE INDEX IF NOT EXISTS unique_username ON TABLE users FIELDS username UNIQUE;
//         DEFINE INDEX IF NOT EXISTS unique_email ON TABLE users FIELDS email UNIQUE;
//     "#;

//     let db = get_db();
//     db.query(query).await?;

//     Ok(())
// }

// pub async fn create_user(input: UserInput) -> Result<()> {
//     let db = get_db();
//     let _r: Option<User> = db.create(("users", &input.uuid)).content(input).await?;
//     Ok(())
// }

// pub async fn get_user_by_name(username: &str) -> Result<Option<User>> {
//     let db = get_db();
//     let query = "SELECT * FROM users WHERE username = $username";
//     let result: Option<User> = db
//         .query(query)
//         .bind(("username", username.to_string()))
//         .await?
//         .take(0)?;
//     Ok(result)
// }

// pub async fn get_user_by_id(user_id: &str) -> Result<Option<User>> {
//     let db = get_db();
//     let r: Option<User> = db.select(("users", user_id)).await?;
//     Ok(r)
// }
