package dev.hg.grantmint.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Root command for the Grantmint CLI.
 *
 * <p>Subcommands: {@code keygen} (generate an Ed25519 signing keypair), the offline {@code verify}
 * and {@code inspect} (no network — {@code grantmint-core} only), and the server-backed {@code
 * issue} / {@code revoke} (plain {@code java.net.http.HttpClient} calls against a running
 * Grantmint server). Offline verification needs no running server, which is the whole point of the
 * signed-token design — see docs/features/LICENSE_TOKEN_FORMAT.md.
 */
@Command(
        name = "grantmint",
        mixinStandardHelpOptions = true,
        version = "grantmint 0.1.0-SNAPSHOT",
        description = "Issue, inspect, revoke, and verify Grantmint licenses.",
        subcommands = {
            KeygenCommand.class,
            VerifyCommand.class,
            InspectCommand.class,
            IssueCommand.class,
            RevokeCommand.class
        })
public final class GrantmintCli implements Callable<Integer> {

    @Override
    public Integer call() {
        // With no subcommand, print usage and exit non-zero (Picocli convention).
        CommandLine.usage(this, System.out);
        return CommandLine.ExitCode.USAGE;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new GrantmintCli()).execute(args);
        System.exit(exitCode);
    }
}
