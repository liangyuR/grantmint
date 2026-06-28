package dev.hg.grantmint.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Root command for the Grantmint CLI.
 *
 * <p>Subcommands — {@code keygen}, {@code issue}, {@code inspect}, {@code revoke}, and the
 * offline {@code verify} — are added in milestone M10. The CLI depends only on
 * {@code grantmint-core}, so offline verification needs no running server. This is the M0
 * skeleton: it wires Picocli and prints usage.
 */
@Command(
        name = "grantmint",
        mixinStandardHelpOptions = true,
        version = "grantmint 0.1.0-SNAPSHOT",
        description = "Issue, inspect, revoke, and verify Grantmint licenses.")
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
