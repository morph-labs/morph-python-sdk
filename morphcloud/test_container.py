# Example 1: Basic usage
from morphcloud.api import MorphCloudClient

client = MorphCloudClient()

# docker_snapshot = (
#     client.snapshots.get("snapshot_5bpzq47e")
#     .setup("systemctl start docker.service")
#     .setup("systemctl start containerd.service")
# )

ubuntu_snapshot_base = client.snapshots.create(
    image_id="morphvm-minimal", vcpus=4, memory=4096, disk_size=8192, digest="4x4x8v2"
)  # .as_container("ubuntu:22.04")


ubuntu_instance = client.instances.start(ubuntu_snapshot_base.id)

breakpoint()

# sets up the container, runs it, and passes through all
# ssh commands into it
ubuntu_instance.as_container("ubuntu:22.04")

print(ubuntu_instance.exec("echo 'export FOO=bar' >> ~/.profile"))
print(ubuntu_instance.exec("echo $FOO"))
breakpoint()

exit()

# Start an instance from a snapshot
instance = client.instances.start("snapshot_5bpzq47e")
instance.wait_until_ready()

# Configure it to use a Docker container
instance.as_container(image="ubuntu:22.04", container_name="my_ubuntu")

with instance.ssh() as ssh:
    ssh.run("apt update -y && apt install -y neofetch")

# Now all SSH connections to this instance will be redirected to the container
print(f"SSH to {instance.id} to access the container directly")


# # Example 2: More advanced usage with ports, volumes and environment variables
# instance = client.instances.start("snapshot_id_with_docker_installed")
# instance.wait_until_ready()

# # Run a PostgreSQL container with port forwarding and data volume
# instance.as_container(
#     image="postgres:13",
#     container_name="my_postgres",
#     ports={5432: 5432},  # Map host port to container port
#     volumes=["/var/lib/postgresql/data:/var/lib/postgresql/data"],
#     env={
#         "POSTGRES_PASSWORD": "mysecretpassword",
#         "POSTGRES_USER": "myuser",
#         "POSTGRES_DB": "mydb"
#     }
# )

# # Expose the PostgreSQL port via HTTP service
# url = instance.expose_http_service("postgres", 5432)
# print(f"PostgreSQL accessible at: {url}")


# # Example 3: Using with the SWE-Gym environment from your example
# environment_id = "web_shopping_s_cart"  # from your example it looks like you're replacing "__" with "_s_"

# instance = client.instances.start("snapshot_id_with_docker_installed")
# instance.wait_until_ready()

# # Configure to use the SWE-Gym container
# instance.as_container(
#     image=f"xingyaoww/sweb.eval.x86_64.{environment_id}",
#     container_name="tty"  # using "tty" to match your example
# )

# print(f"Instance {instance.id} is now configured with the {environment_id} environment")
# print("SSH into the instance to access the environment directly")
