from morphcloud.api import MorphCloudClient

if __name__ == "__main__":
    client = MorphCloudClient()

    # snapshot = client.snapshots.create(image_id="morphvm-minimal", vcpus=1, memory=1024, disk_size=4096, digest="1x1x4")
    # inst = client.instances.start(snapshot.id)
    # print(f"{inst=}")
    inst = client.instances.get("morphvm_k9yntifi")

    inst.update_ttl(10, ttl_action="pause")
