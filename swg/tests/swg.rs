use swg::{SecureWebGateway, UrlCategory, WebAccessAction, WebPolicy};

#[test]
fn categorizes_social_media() {
    let gw = SecureWebGateway::new();
    assert!(matches!(
        gw.categorize_url("https://facebook.com/page"),
        UrlCategory::SocialMedia
    ));
}

#[test]
fn policy_blocks_domain() {
    let gw = SecureWebGateway::new();
    let mut policy = WebPolicy::new("block-gambling");
    policy.blocked_domains.push("gambling.test".into());
    policy.default_action = WebAccessAction::Block;
    gw.add_policy(policy);

    let result = gw.evaluate("https://gambling.test/play").unwrap();
    assert_eq!(result.action, WebAccessAction::Block);
}
