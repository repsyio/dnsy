//! Interop with real DNS tools. Each test skips (and says so) when its tool is not installed.

use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Harness, MtlsPolicy, Opts};
use tokio::process::Command;

async fn have(tool: &str, flag: &str) -> bool {
    Command::new(tool)
        .arg(flag)
        .output()
        .await
        .is_ok_and(|o| o.status.success())
}

async fn run(tool: &str, args: &[String]) -> String {
    let out = Command::new(tool)
        .args(args)
        .output()
        .await
        .expect("run tool");
    assert!(
        out.status.success(),
        "{tool} {args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_owned()).collect()
}

#[tokio::test]
async fn dig_kdig_interop() {
    let dig_ok = have("dig", "-v").await;
    let kdig_ok = have("kdig", "-V").await;
    if !dig_ok && !kdig_ok {
        eprintln!("skipped: neither dig nor kdig is installed");
        return;
    }
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Off),
        same_udp_tcp_port: true,
        ..Opts::default().zone("example.test.", example_zone())
    })
    .await;

    if dig_ok {
        let port = h.udp.port().to_string();
        let mut base = strings(&["@127.0.0.1", "-p"]);
        base.push(port);
        for extra in [&[][..], &["+tcp"][..], &["+bufsize=4096"][..]] {
            let mut args = base.clone();
            args.extend(strings(&[
                "www.example.test",
                "A",
                "+short",
                "+time=5",
                "+tries=1",
            ]));
            args.extend(strings(extra));
            assert_eq!(run("dig", &args).await.trim(), "192.0.2.7", "dig {extra:?}");
        }
        // NXDOMAIN shows in the status line.
        let mut args = base.clone();
        args.extend(strings(&["nope.example.test", "A", "+time=5", "+tries=1"]));
        assert!(run("dig", &args).await.contains("status: NXDOMAIN"));
        // The 40-record answer overflows 512 octets: dig retries over TCP by itself.
        let mut args = base;
        args.extend(strings(&[
            "many.example.test",
            "A",
            "+short",
            "+time=5",
            "+tries=2",
            "+noedns",
        ]));
        assert_eq!(run("dig", &args).await.lines().count(), 40);
    }
    if kdig_ok {
        let ca = h.dir.path().join("ca.pem");
        let args = vec![
            "@127.0.0.1".to_owned(),
            "-p".to_owned(),
            h.dot.unwrap().port().to_string(),
            "+tls".to_owned(),
            format!("+tls-ca={}", ca.display()),
            "+tls-hostname=localhost".to_owned(),
            "www.example.test".to_owned(),
            "A".to_owned(),
            "+short".to_owned(),
        ];
        assert!(run("kdig", &args).await.contains("192.0.2.7"));
    }
}
