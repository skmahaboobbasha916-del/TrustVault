"""One-time CLI for promoting an existing TrustVault user to admin."""

import argparse
import sys

from services.admin_provisioning_service import (
    AdminProvisioningError,
    provision_first_admin,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Promote one existing user to the first TrustVault admin."
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Email address of the existing user to promote.",
    )
    args = parser.parse_args(argv)
    email = args.email.strip().lower()
    if not email:
        parser.error("--email must not be empty")

    confirmation = f"PROMOTE {email} TO ADMIN"
    try:
        typed_confirmation = input(
            f"This will promote the existing account {email}. "
            f"Type '{confirmation}' to continue: "
        )
    except (EOFError, KeyboardInterrupt):
        print("Admin provisioning cancelled.", file=sys.stderr)
        return 1

    if typed_confirmation.strip() != confirmation:
        print("Admin provisioning cancelled.", file=sys.stderr)
        return 1

    try:
        user_id = provision_first_admin(email)
    except (ValueError, AdminProvisioningError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("Admin provisioning failed.", file=sys.stderr)
        return 1

    print(f"Admin role provisioned for user ID {user_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
