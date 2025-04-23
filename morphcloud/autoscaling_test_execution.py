import asyncio
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List

import pandas as pd

# Import the Morph Cloud Python client
# (Ensure you've installed/available morphcloud.api per your environment)
from morphcloud.api import (Instance, InstanceExecResponse, MorphCloudClient,
                            Snapshot)


@dataclass
class CandidatePatch:
    """Represents a patch to be tested against a snapshot (VM)."""

    id: str
    patch_content: str


@dataclass
class SyntheticTestSuite:
    """Represents a synthetic test suite with a base snapshot and some file set to be tested."""

    snapshot_id: str
    files: Dict[str, str]  # mapping local (temp) file name -> content
    entrypoint: str  # e.g. "run_tests.sh"


@dataclass
class TestExecutionResult:
    """Holds the outcome of running a specific patch on a specific test suite."""

    candidate_patch_id: str
    test_suite_snapshot_id: str
    passed: bool
    output: str
    execution_time: float


@dataclass
class TestExecutionConfig:
    """Controls concurrency and any other relevant test execution settings."""

    max_workers: int = 16


async def _evaluate_patch(
    morph_client: MorphCloudClient,
    candidate_patch: CandidatePatch,
    candidate_test_suite: SyntheticTestSuite,
) -> TestExecutionResult:
    """
    1. Spin up an instance from the test suite's snapshot.
    2. Copy patch + test files to the instance and apply them.
    3. Run the test suite's entrypoint.
    4. Collect output + record pass/fail in TestExecutionResult.
    5. Stop the instance.
    """
    start_time = time.time()

    # 1) Spin up an instance from the snapshot
    instance = await morph_client.instances.astart(candidate_test_suite.snapshot_id)
    try:
        # Wait until the instance is fully ready
        await instance.await_until_ready(timeout=300)

        # 2a) Copy the patch content to the instance.
        #     We'll write the patch content to a local temp file, then sync to the instance.
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as patch_file:
            patch_file.write(candidate_patch.patch_content)
            local_patch_path = patch_file.name

        # We'll put the patch file at /tmp/candidate.patch on the instance
        remote_patch_path = "/tmp/candidate.patch"

        # The 'sync' method is synchronous, so we call it in a thread:
        await asyncio.to_thread(
            instance.sync,
            source_path=local_patch_path,
            dest_path=f"{instance.id}:{remote_patch_path}",
            delete=False,
            dry_run=False,
        )

        # 2b) Apply the patch. We'll use 'patch -p1 < /tmp/candidate.patch' as a placeholder.
        #     The aexec method is asynchronous.
        patch_result: InstanceExecResponse = await instance.aexec(
            f"patch -p1 < {remote_patch_path}"
        )
        if patch_result.exit_code != 0:
            # If patch fails, we can decide to fail early or proceed
            print(f"Warning: patch {candidate_patch.id} failed to apply.")

        # 2c) Copy test suite files to the instance:
        #     We'll place them into /tmp/test_suite_files/ for this demonstration.
        remote_test_dir = "/tmp/test_suite_files"
        for filename, content in candidate_test_suite.files.items():
            # Write each file to a local temp location
            with tempfile.NamedTemporaryFile(delete=False, mode="w") as tf:
                tf.write(content)
                local_file_path = tf.name

            # Build a remote path: /tmp/test_suite_files/<basename_of_filename>
            remote_file_path = f"{remote_test_dir}/{os.path.basename(filename)}"
            # Ensure remote directory structure via a single "mkdir -p"
            await instance.aexec(f"mkdir -p {remote_test_dir}")

            # Sync each file
            await asyncio.to_thread(
                instance.sync,
                source_path=local_file_path,
                dest_path=f"{instance.id}:{remote_file_path}",
                delete=False,
                dry_run=False,
            )

        # 3) Run the test suite's entrypoint. We'll assume it's something like "bash run_tests.sh".
        #    Let's say we do it from the remote_test_dir.
        test_command = f"cd {remote_test_dir} && bash {candidate_test_suite.entrypoint}"
        exec_response: InstanceExecResponse = await instance.aexec(test_command)

        # 4) Collect output + pass/fail
        #    We'll do a simple pass/fail check. Real logic would parse exec_response.stdout/stderr
        #    or logs. For demonstration, let's say exit_code 0 -> passed.
        passed = exec_response.exit_code == 0
        output = exec_response.stdout + "\n" + exec_response.stderr
        execution_time = time.time() - start_time

        return TestExecutionResult(
            candidate_patch_id=candidate_patch.id,
            test_suite_snapshot_id=candidate_test_suite.snapshot_id,
            passed=passed,
            output=output,
            execution_time=execution_time,
        )

    finally:
        # 5) Stop the instance
        await instance.astop()


async def _calculate_test_execution_array(
    morph_client: MorphCloudClient,
    candidate_test_suites: List[SyntheticTestSuite],
    candidate_patches: List[CandidatePatch],
    test_execution_config: TestExecutionConfig,
) -> pd.DataFrame:
    """
    Evaluate each (patch, test_suite) pair asynchronously, but limit concurrency
    via a semaphore. Return a pandas DataFrame with one row per patch and one
    column per test suite, containing a TestExecutionResult for each cell.
    """
    sem = asyncio.Semaphore(test_execution_config.max_workers)

    # We'll store results in a list of (patch_id, snapshot_id, TestExecutionResult).
    # Then we convert this to a DataFrame in a pivoted format.
    results_list = []

    async def _worker(patch: CandidatePatch, test_suite: SyntheticTestSuite):
        async with sem:
            r = await _evaluate_patch(morph_client, patch, test_suite)
            return r

    # Evaluate patch vs test_suite in parallel with gather
    # We'll nest patches as rows, test_suites as columns.
    for patch in candidate_patches:
        # Evaluate this patch across all test suites concurrently
        row_results = await asyncio.gather(
            *[_worker(patch, ts) for ts in candidate_test_suites]
        )
        # Add them to our results list
        for rr in row_results:
            results_list.append(rr)

    # Convert results to a DataFrame.
    # Each row is (patch, test_suite, passed, output, execution_time).
    # We'll pivot so that columns are test_suite IDs and rows are patch IDs, and
    # values are the actual TestExecutionResult object. You can store just 'passed' etc.
    rows = []
    for result in results_list:
        rows.append(
            {
                "patch_id": result.candidate_patch_id,
                "snapshot_id": result.test_suite_snapshot_id,
                "passed": result.passed,
                "output": result.output,
                "execution_time": result.execution_time,
                "object": result,  # store entire object if you like
            }
        )

    df_long = pd.DataFrame(rows)

    # We'll build a pivot table:
    # Rows = patch_id, Columns = snapshot_id, Values = entire TestExecutionResult object
    # (or we can pivot on 'passed' or 'output', etc.)
    df_pivot = df_long.pivot(index="patch_id", columns="snapshot_id", values="object")

    # Alternatively, you could keep df_long if you prefer tidy data.
    return df_pivot


async def main():
    # 1) Initialize Morph Cloud client
    #    Provide your API key directly or via environment variable MORPH_API_KEY
    morph_client = MorphCloudClient(api_key="YOUR_API_KEY")

    # 2) Define sample patches
    candidate_patches = [
        CandidatePatch(id="patch1", patch_content="diff --git a/file b/file\n..."),
        CandidatePatch(id="patch2", patch_content="diff --git a/file b/file\n..."),
    ]

    # 3) Define sample test suites
    #    We'll assume they each have a snapshot_id that is valid in your Morph Cloud environment.
    #    The 'files' dict is local_name -> content. We'll copy them to /tmp/test_suite_files/ on the instance.
    candidate_test_suites = [
        SyntheticTestSuite(
            snapshot_id="snapshot_xxxx",
            files={
                "test.sh": "#!/usr/bin/env bash\necho 'Running tests...'\nexit 0\n",
            },
            entrypoint="test.sh",
        ),
        SyntheticTestSuite(
            snapshot_id="snapshot_yyyy",
            files={
                "test.sh": "#!/usr/bin/env bash\necho 'Simulating a failure...'\nexit 1\n",
            },
            entrypoint="test.sh",
        ),
    ]

    # 4) Define how many concurrent tasks are allowed
    config = TestExecutionConfig(max_workers=4)

    # 5) Calculate the test execution array, returning a DataFrame
    df = await _calculate_test_execution_array(
        morph_client, candidate_test_suites, candidate_patches, config
    )

    # 6) Print out the DataFrame
    print("Final pivoted DataFrame (index=patch_id, columns=snapshot_id):")
    print(df)

    # If you'd like, you can also inspect individual results:
    print("\nSample cell from the DataFrame (TestExecutionResult object):")
    sample_result_object = df.loc["patch1", "snapshot_xxxx"]
    print("passed =", sample_result_object.passed)
    print("output =", sample_result_object.output)
    print("execution_time =", sample_result_object.execution_time)


if __name__ == "__main__":
    asyncio.run(main())
