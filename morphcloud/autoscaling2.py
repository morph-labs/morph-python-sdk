import asyncio

from morphcloud.api import (Instance, InstanceStatus, MorphCloudClient,
                            SnapshotAPI)

CLIENT = MorphCloudClient()

MICROSERVICE_SNAPSHOT_ID = "snapshot_z7x2gad0"

sem = asyncio.Semaphore(8)

ExecutionTask = ...
ExecutionResult = ...

tasks: List[ExecutionTask]


# now just launch all these futures
async def _execute_task(task: ExecutionTask) -> ExecutionResult:
    async with sem:

        # this context manager destroy the VM instance after the work is done
        async with client.instances.astart(MICROSERVICE_SNAPSHOT_ID) as vm:
            # do something like await vm.async("/tmp/my_candidate_patch.diff", dest)
            test_result = (
                ...
            )  # do work with the vm, e.g. await vm.aexec("..."), parse stdout

            return test_result


futs = []

for task in tasks:
    futs.append(asyncio.create_task(_execute_task(task)))

result = list(asyncio.gather(*futs))

"""
for the AI SWE case:
- set up an async channel or request queue and parallelize the 
"""
