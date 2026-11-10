use std::error::Error;
use std::process::ExitCode;

use clap::{crate_version, value_parser, Arg, ArgMatches, Command};
use snmprs_lib::base_client::BaseClient;
use snmprs_lib::snmp_msg_builder::{SnmpMessageBuilder, SnmpV2MessageBuilder};

fn actions() -> Vec<Command> {
    vec![Command::new("get")
        .about("SNMP Get command")
        .arg_required_else_help(true)
        .arg(Arg::new("oid").help("SNMP OID").required(true))]
}

fn cli() -> Command {
    Command::new("snmprs")
        .about("A sample SNMP v2/3 client")
        .version(crate_version!())
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("host")
                .help("IP Address or host of the SNMP agent")
                .short('a')
                .required(true),
        )
        .arg(
            Arg::new("port")
                .help("UDP port of the SNMP agent")
                .short('p')
                .value_parser(value_parser!(u16))
                .default_value("161"),
        )
        .subcommands([
            Command::new("v2")
                .about("SNMP V2")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .arg(Arg::new("community").help("Community string").short('c'))
                .subcommands(actions()),
            Command::new("v3")
                .about("SNMP V3")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .arg(
                    Arg::new("pass_protocol")
                        .help(
                            "Authentication passphrase protocol (MD5, SHA, SHA-[224|256|384|512])",
                        )
                        .short('e'),
                )
                .arg(
                    Arg::new("passphrase")
                        .help("Authentication passphrase")
                        .short('A'),
                )
                .arg(
                    Arg::new("level")
                        .help("Security level (noAuthNoPriv|authNoPriv|authPriv)")
                        .short('l')
                        .required(true),
                )
                .arg(
                    Arg::new("username")
                        .help("Authentication username")
                        .short('u'),
                )
                .arg(
                    Arg::new("priv_protocol")
                        .help("Privacy passphrase protocol (DES, AES-[128|192|256])")
                        .short('x'),
                )
                .arg(Arg::new("privacy").help("Privacy passphrase").short('X'))
                .subcommands(actions()),
        ])
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn run_v2(client: &mut BaseClient, args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let community = args
        .get_one::<String>("community")
        .cloned()
        .unwrap_or_default();
    let msg_builder = SnmpV2MessageBuilder::new(community);

    if let Some(get_cmd) = args.subcommand_matches("get") {
        let oid = get_cmd.get_one::<String>("oid").expect("OID is required");

        let request = msg_builder.get(oid)?;
        client.send(&request.encode()?)?;

        // Responses can't be decoded yet, so show the raw message.
        println!("{}", to_hex(client.receive()?));
    }

    Ok(())
}

fn run(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let host = args
        .get_one::<String>("host")
        .expect("IP or host is required");
    let port = *args.get_one::<u16>("port").expect("port has a default");

    if let Some(v2_ver) = args.subcommand_matches("v2") {
        return run_v2(&mut BaseClient::new(host, port)?, v2_ver);
    }

    Err("SNMPv3 is not implemented yet".into())
}

fn main() -> ExitCode {
    match run(&cli().get_matches()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Print the whole chain so the underlying cause (such as the OS error) is shown.
            eprint!("error: {}", e);
            let mut source = e.source();
            while let Some(cause) = source {
                eprint!(": {}", cause);
                source = cause.source();
            }
            eprintln!();
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_definition() {
        cli().debug_assert();
    }

    // `debug_assert` only checks the definition, so also read the arguments back the
    // way `run` does: a mismatched argument id panics here instead of at runtime.
    #[test]
    fn test_run_reads_defined_arguments() {
        let args = cli().get_matches_from([
            "snmprs",
            "-a",
            "localhost",
            "v2",
            "-c",
            "public",
            "get",
            "1.3.6",
        ]);

        assert_eq!(args.get_one::<String>("host").unwrap(), "localhost");
        assert_eq!(*args.get_one::<u16>("port").unwrap(), 161);

        let v2 = args.subcommand_matches("v2").unwrap();
        assert_eq!(v2.get_one::<String>("community").unwrap(), "public");
        let get = v2.subcommand_matches("get").unwrap();
        assert_eq!(get.get_one::<String>("oid").unwrap(), "1.3.6");
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0]), "000fa0");
    }
}
