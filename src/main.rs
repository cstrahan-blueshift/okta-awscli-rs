#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let aws_auth = AwsAuth::new(None, String::from("default"));
    if !aws_auth.check_sts_token().await {
        get_credentials(aws_auth).await;
    }
    // let config = aws_config::load_from_env().await;
    // let client = iam::Client::new(&config);

    println!("Done");
}

async fn get_credentials(aws_auth: AwsAuth) {}

struct AwsAuth {
    profile: String,
    okta_profile: String,
    role: Option<String>,
}

use std::path::PathBuf;

//    aws_auth = AwsAuth(profile, okta_profile, lookup, verbose, logger)
use configparser::ini::Ini;

// home_dir = os.path.expanduser('~')
// self.creds_dir = home_dir + "/.aws"
// self.creds_file = self.creds_dir + "/credentials"

use aws_sdk_iam as iam;
use aws_sdk_sts as sts;
use aws_smithy_http::result::SdkError;
use once_cell::sync::Lazy;
use sts::error::{GetCallerIdentityError, GetCallerIdentityErrorKind};

static CREDS_FILE: Lazy<PathBuf> = Lazy::new(|| {
    let mut path = dirs::home_dir().expect("couldn't get home directory");
    path.push(".aws");
    path.push("credentials");
    path
});

static OKTA_CONFIG_FILE: Lazy<PathBuf> = Lazy::new(|| {
    let mut path = dirs::home_dir().expect("couldn't get home directory");
    path.push(".okta-aws");
    path
});

impl AwsAuth {
    pub fn new(profile: Option<String>, okta_profile: String) -> Self {
        let conf = std::fs::read_to_string(OKTA_CONFIG_FILE.as_path()).unwrap();
        let mut config = Ini::new();
        config.read(conf).expect("okta conf parse");

        let role = config.get(&okta_profile, "role");
        let profile = profile
            .or_else(|| config.get(&okta_profile, "profile"))
            .unwrap_or(String::from("default"));

        Self {
            profile,
            okta_profile,
            role,
        }
    }

    pub async fn check_sts_token(&self) -> bool {
        if !CREDS_FILE.exists() {
            return false;
        }

        let aws_creds_str = std::fs::read_to_string(CREDS_FILE.as_path()).unwrap();
        let mut aws_creds = Ini::new();
        aws_creds.read(aws_creds_str).expect("aws creds parse");

        if !aws_creds.sections().contains(&self.profile) {
            // TODO: this is O(n)
            // no existing credentials
            return false;
        }

        let aws_config = aws_config::load_from_env().await;
        let sts_client = sts::Client::new(&aws_config);

        let res = sts_client.get_caller_identity().send().await;

        if let Err(ref err) = res {
            match err {
                err if is_expired_token(err) => {
                    // expired token
                    return false;
                }
                err if is_missing_credentials(err) => {
                    // missing creds
                    return false;
                }
                _ => {
                    // unkown error
                    return false;
                }
            }
        }

        self.set_default_profile(&mut aws_creds).await;

        true
    }

    pub async fn set_default_profile(&self, config: &mut Ini) {
        if let Some(profile_section) = config.get_map_ref().get(&self.profile) {
            let entries: Vec<(String, Option<String>)> = profile_section
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (key, value) in entries.into_iter() {
                config.set("default", &key, value);
            }

            config
                .write(CREDS_FILE.as_path())
                .expect("write creds default profile");
        }
    }
}

fn is_missing_credentials<E, R>(err: &SdkError<E, R>) -> bool {
    use aws_sig_auth::middleware::SigningStageError;

    if let SdkError::ConstructionFailure(ref err) = err {
        let signing_stage_error = err.downcast_ref::<SigningStageError>();
        return matches!(
            signing_stage_error,
            Some(SigningStageError::MissingCredentials)
        );
    }

    false
}

fn is_expired_token(err: &SdkError<GetCallerIdentityError>) -> bool {
    match err {
        SdkError::ServiceError { err, .. } => err.meta().code() == Some("ExpiredToken"),
        _ => false,
    }
}

struct OktaAuth {}

impl OktaAuth {}
