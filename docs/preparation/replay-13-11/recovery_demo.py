#!/usr/bin/env python3
"""Run ONLY canned synthetic recovery scenarios; no real input or network option."""
import argparse
import sys

from replay_recovery import FakeWorkServer, RecoveryError, replay
from synthetic_recovery import LostResponse, RejectedBatch, synthetic_manifest


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RecoveryError("invalid_arguments")


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--scenario", choices=("success", "response-loss", "failed-batch"), required=True)
    try:
        args = parser.parse_args(argv)
        factory = {"success": FakeWorkServer, "response-loss": LostResponse, "failed-batch": RejectedBatch}
        server = factory[args.scenario]({("navlun", "target")})
        manifest = synthetic_manifest()
        replay(manifest, args.receipt, server)
        # Reopen the durable receipt, retaining ONLY the synthetic destination.
        # No CLI resume flag: a fresh invocation has no persistent fake server.
        return replay(manifest, args.receipt, server, resume=True)
    except RecoveryError as error:
        print("recovery_demo: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError):
        print("recovery_demo: input_or_output_failure", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
