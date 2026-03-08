import os

from morphcloud.api import MorphCloudClient


def main() -> None:
    client = MorphCloudClient()

    print("Listing devboxes...")
    devboxes = client.devbox.devboxes_core.list_devboxes()
    print(devboxes)

    template_id = os.environ.get("MORPH_DEVBOX_TEMPLATE_ID")
    if not template_id:
        print("Set MORPH_DEVBOX_TEMPLATE_ID to start an instant devbox from a template.")
        return

    name = os.environ.get("MORPH_DEVBOX_NAME")
    print(f"Starting devbox from template {template_id}...")
    devbox = client.devbox.start(template_id=template_id, name=name)
    print(f"Devbox created: {devbox.id}")


if __name__ == "__main__":
    main()

