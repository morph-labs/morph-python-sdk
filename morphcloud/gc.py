"""
Garbage Collection module for MorphCloud snapshots.

Implements core GC logic: tree traversal, reachability analysis, and cleanup candidate identification.
"""

import logging
from typing import List, Set, Dict
from dataclasses import dataclass

from morphcloud.api import Snapshot, Instance, InstanceStatus

logger = logging.getLogger(__name__)


@dataclass
class SnapshotClassification:
    """Classification of snapshots for garbage collection."""
    gc_roots: Set[str]          # Never delete - active instances, tagged snapshots
    reachable: Set[str]         # Never delete - ancestors of GC roots
    unreachable: Set[str]       # Safe to delete - no path to any GC root


class SnapshotGarbageCollector:
    """Core garbage collection engine for snapshots."""
    
    def __init__(self):
        self.snapshot_lookup: Dict[str, Snapshot] = {}
        
    def classify_snapshots(self, snapshots: List[Snapshot], instances: List[Instance]) -> SnapshotClassification:
        """Classify all snapshots into GC categories."""
        self.snapshot_lookup = {s.id: s for s in snapshots}
        
        classification = SnapshotClassification(
            gc_roots=set(),
            reachable=set(),
            unreachable=set()
        )
        
        # Find GC roots
        classification.gc_roots = self._find_gc_roots(snapshots, instances)
        
        # Mark reachable snapshots by traversing parent chains
        for root_id in classification.gc_roots:
            self._mark_reachable_chain(root_id, classification.reachable)
        
        # Identify unreachable snapshots
        for snapshot in snapshots:
            if snapshot.id not in classification.reachable:
                classification.unreachable.add(snapshot.id)
        
        logger.info(f"GC analysis: {len(classification.reachable)} reachable, "
                   f"{len(classification.unreachable)} unreachable")
        
        return classification
    
    def _find_gc_roots(self, snapshots: List[Snapshot], instances: List[Instance]) -> Set[str]:
        """Find all GC roots (snapshots that should never be deleted)."""
        gc_roots = set()
        
        # Active instance snapshots
        active_statuses = {InstanceStatus.READY, InstanceStatus.PAUSED, InstanceStatus.PENDING}
        for instance in instances:
            if instance.status in active_statuses:
                gc_roots.add(instance.refs.snapshot_id)
        
        # Tagged and explicitly protected snapshots
        for snapshot in snapshots:
            if snapshot.metadata:
                if snapshot.metadata.get("tag") or snapshot.metadata.get("gc_keep") == "true":
                    gc_roots.add(snapshot.id)
        
        return gc_roots
    
    def _mark_reachable_chain(self, snapshot_id: str, reachable: Set[str]):
        """Mark all snapshots in the parent chain as reachable."""
        visited = set()  # Cycle detection
        current_id = snapshot_id
        
        while current_id and len(visited) < 1000:  # Max depth protection
            if current_id in visited:
                logger.warning(f"Cycle detected in parent chain starting from {snapshot_id}")
                break
            
            if current_id in reachable:
                break  # Already processed
            
            visited.add(current_id)
            reachable.add(current_id)
            
            # Find parent
            snapshot = self.snapshot_lookup.get(current_id)
            if not snapshot or not snapshot.metadata:
                break  # Reached root
                
            parent_id = snapshot.metadata.get("parent_snapshot_id")
            if not parent_id:
                break  # Reached root
                
            if parent_id not in self.snapshot_lookup:
                logger.warning(f"Broken chain: {current_id} points to non-existent parent {parent_id}")
                break
                
            current_id = parent_id
    
    def get_cleanup_candidates(self, classification: SnapshotClassification) -> List[str]:
        """Get list of snapshot IDs that are safe to delete."""
        return list(classification.unreachable)


def cleanup_snapshots_by_target(client, target: str, failed_days: int = 7, stale_days: int = 30, stuck_hours: int = 24, inactive_days: int = 7, metadata_criteria: Dict = None, override_gc_protection: bool = False, dry_run: bool = True) -> Dict[str, any]:
    """
    Run targeted snapshot cleanup based on cleanup strategy.
    
    Args:
        client: MorphCloudClient instance
        target: Cleanup target ("unused", "inactive-branches", "metadata")
        failed_days: Delete failed snapshots older than N days
        stale_days: Delete stale unreachable snapshots older than N days
        stuck_hours: Delete stuck snapshots older than N hours
        inactive_days: Delete inactive branches with no activity for N days
        metadata_criteria: Dict with metadata matching criteria
        override_gc_protection: Allow deletion of GC roots
        dry_run: If True, only identifies candidates without deleting
        
    Returns:
        Dict with cleanup results
    """
    import time
    from morphcloud.api import ApiError, SnapshotStatus
    
    logger.info(f"Starting {target} cleanup (dry_run={dry_run})")
    
    # Fetch all snapshots and instances
    snapshots = client.snapshots.list()
    instances = client.instances.list()
    
    current_time = time.time()
    candidates = []
    
    if target == "unused":
        # Clean unhealthy snapshots: unreachable + failed + stuck
        candidates = (
            _get_unreachable_candidates(snapshots, instances) +
            _get_failed_candidates(snapshots, failed_days, current_time) +
            _get_stuck_candidates(snapshots, stuck_hours, current_time)
        )
        # Remove duplicates
        candidates = list(set(candidates))
        
        # Apply stale filter to unreachable snapshots
        if stale_days != 30:  # Only apply if user changed default
            stale_candidates = _get_stale_candidates(snapshots, instances, stale_days, current_time)
            unreachable_candidates = _get_unreachable_candidates(snapshots, instances)
            # Replace unreachable with stale-filtered version
            candidates = [c for c in candidates if c not in unreachable_candidates]
            candidates.extend(stale_candidates)
            candidates = list(set(candidates))
            
    elif target == "inactive-branches":
        candidates = _get_inactive_branch_candidates(snapshots, instances, inactive_days, current_time)
        
    elif target == "metadata":
        candidates = _get_metadata_candidates(snapshots, instances, metadata_criteria, override_gc_protection)
        
    else:
        raise ValueError(f"Unknown target: {target}. Valid targets are: unused, inactive-branches, metadata")
    
    # Prepare results
    results = {
        "deleted": [],
        "errors": [],
        "dry_run": dry_run,
        "target": target,
        "total_snapshots": len(snapshots),
        "candidates": len(candidates)
    }
    
    # Process deletion candidates
    for snapshot_id in candidates:
        if dry_run:
            results["deleted"].append(snapshot_id)
            logger.info(f"[DRY RUN] Would delete snapshot: {snapshot_id}")
        else:
            try:
                snapshot = client.snapshots.get(snapshot_id)
                snapshot.delete()
                results["deleted"].append(snapshot_id)
                logger.info(f"Deleted snapshot: {snapshot_id}")
            except ApiError as e:
                error_info = {
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                    "status_code": getattr(e, 'status_code', None)
                }
                results["errors"].append(error_info)
                logger.error(f"Failed to delete snapshot {snapshot_id}: {e}")
            except Exception as e:
                error_info = {
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                    "status_code": None
                }
                results["errors"].append(error_info)
                logger.error(f"Unexpected error deleting snapshot {snapshot_id}: {e}")
    
    # Log summary
    if dry_run:
        logger.info(f"[DRY RUN] Would delete {len(results['deleted'])} {target} snapshots")
    else:
        logger.info(f"Deleted {len(results['deleted'])} {target} snapshots, {len(results['errors'])} errors")
    
    return results


def _get_unreachable_candidates(snapshots: List, instances: List) -> List[str]:
    """Get unreachable snapshot candidates using GC analysis."""
    gc = SnapshotGarbageCollector()
    classification = gc.classify_snapshots(snapshots, instances)
    return gc.get_cleanup_candidates(classification)


def _get_time_filtered_candidates(snapshots: List, time_filter: dict, current_time: float) -> List[str]:
    """Get time-filtered snapshot candidates based on status and age criteria."""
    from morphcloud.api import SnapshotStatus
    
    candidates = []
    
    for snapshot in snapshots:
        if _is_protected_snapshot(snapshot):
            continue
            
        for filter_config in time_filter.get('filters', []):
            status_match = snapshot.status in filter_config['statuses']
            time_match = snapshot.created < (current_time - filter_config['seconds'])
            
            if status_match and time_match:
                candidates.append(snapshot.id)
                break  # Only add once per snapshot
    
    return candidates


def _get_failed_candidates(snapshots: List, failed_days: int, current_time: float) -> List[str]:
    """Get failed snapshot candidates older than failed_days."""
    from morphcloud.api import SnapshotStatus
    return _get_time_filtered_candidates(snapshots, {
        'filters': [{'statuses': [SnapshotStatus.FAILED], 'seconds': failed_days * 24 * 60 * 60}]
    }, current_time)


def _get_stuck_candidates(snapshots: List, stuck_hours: int, current_time: float) -> List[str]:
    """Get snapshots stuck in PENDING/DELETING states for stuck_hours."""
    from morphcloud.api import SnapshotStatus
    return _get_time_filtered_candidates(snapshots, {
        'filters': [{'statuses': [SnapshotStatus.PENDING, SnapshotStatus.DELETING], 'seconds': stuck_hours * 60 * 60}]
    }, current_time)


def _get_stale_candidates(snapshots: List, instances: List, stale_days: int, current_time: float) -> List[str]:
    """Get stale unreachable snapshot candidates older than stale_days."""
    unreachable = _get_unreachable_candidates(snapshots, instances)
    cutoff_time = current_time - (stale_days * 24 * 60 * 60)
    snapshot_lookup = {s.id: s for s in snapshots}
    
    return [sid for sid in unreachable if snapshot_lookup.get(sid) and snapshot_lookup[sid].created < cutoff_time]


def _get_inactive_branch_candidates(snapshots: List, instances: List, inactive_days: int, current_time: float) -> List[str]:
    """Get inactive branch candidates - branches with no activity for inactive_days."""
    from morphcloud.api import InstanceStatus
    
    # Build parent-child relationship maps
    children_map = {}  # parent_id -> [child_ids]
    parent_map = {}    # child_id -> parent_id
    
    for snapshot in snapshots:
        if snapshot.metadata and snapshot.metadata.get("parent_snapshot_id"):
            parent_id = snapshot.metadata["parent_snapshot_id"]
            parent_map[snapshot.id] = parent_id
            
            if parent_id not in children_map:
                children_map[parent_id] = []
            children_map[parent_id].append(snapshot.id)
    
    # Find active snapshots (recently accessed)
    active_snapshots = set()
    cutoff_time = current_time - (inactive_days * 24 * 60 * 60)
    
    # Mark snapshots with recent instances as active
    for instance in instances:
        if instance.status in [InstanceStatus.READY, InstanceStatus.PAUSED, InstanceStatus.PENDING]:
            active_snapshots.add(instance.refs.snapshot_id)
    
    # Also mark recent snapshots as active (approximation of activity)
    for snapshot in snapshots:
        if snapshot.created > cutoff_time:
            active_snapshots.add(snapshot.id)
    
    # Find branch points (snapshots with multiple children)
    branch_points = {parent_id for parent_id, children in children_map.items() if len(children) > 1}
    
    inactive_candidates = []
    
    # For each branch point, check if any branches are inactive
    for branch_point in branch_points:
        children = children_map[branch_point]
        
        for child_id in children:
            # Check if this branch has any active descendants
            if not _branch_has_active_descendants(child_id, children_map, active_snapshots):
                # This branch is inactive - add it and all its descendants
                inactive_candidates.extend(_get_branch_descendants(child_id, children_map, snapshots))
    
    # Filter out protected snapshots
    return [snap_id for snap_id in inactive_candidates if not _is_protected_snapshot(snap_id, snapshots)]


def _branch_has_active_descendants(snapshot_id: str, children_map: Dict[str, List[str]], active_snapshots: Set[str]) -> bool:
    """Check if a branch has any active descendants."""
    if snapshot_id in active_snapshots:
        return True
    
    # Check all descendants
    children = children_map.get(snapshot_id, [])
    for child_id in children:
        if _branch_has_active_descendants(child_id, children_map, active_snapshots):
            return True
    
    return False


def _get_branch_descendants(snapshot_id: str, children_map: Dict[str, List[str]], snapshots: List) -> List[str]:
    """Get all descendants of a snapshot (including itself)."""
    descendants = [snapshot_id]
    
    children = children_map.get(snapshot_id, [])
    for child_id in children:
        descendants.extend(_get_branch_descendants(child_id, children_map, snapshots))
    
    return descendants


def _is_protected_snapshot(snapshot_or_id, snapshots: List = None) -> bool:
    """Check if a snapshot is protected from deletion."""
    # Handle both snapshot object and ID
    if isinstance(snapshot_or_id, str):
        if not snapshots:
            return False
        snapshot = next((s for s in snapshots if s.id == snapshot_or_id), None)
        if not snapshot:
            return False
    else:
        snapshot = snapshot_or_id
    
    if not snapshot.metadata:
        return False
    
    # Protected by tag or explicit protection
    return snapshot.metadata.get("tag") or snapshot.metadata.get("gc_keep") == "true"



def _get_metadata_candidates(snapshots: List, instances: List, metadata_criteria: Dict, override_gc_protection: bool) -> List[str]:
    """Get snapshots matching metadata criteria."""
    import fnmatch
    
    if not metadata_criteria:
        return []
    
    candidates = []
    gc_roots_skipped = []
    
    # Get GC roots for protection checking
    gc = SnapshotGarbageCollector()
    gc_roots = gc._find_gc_roots(snapshots, instances)
    
    for snapshot in snapshots:
        # Check if snapshot matches metadata criteria
        if _snapshot_matches_metadata_criteria(snapshot, metadata_criteria):
            # Check GC protection
            if snapshot.id in gc_roots and not override_gc_protection:
                gc_roots_skipped.append(snapshot.id)
                continue
            
            candidates.append(snapshot.id)
    
    # Log GC roots that were skipped
    if gc_roots_skipped:
        logger.warning(f"Skipped {len(gc_roots_skipped)} GC roots. Use --override-gc-protection to include them.")
    
    return candidates


def _snapshot_matches_metadata_criteria(snapshot, metadata_criteria: Dict) -> bool:
    """Check if a snapshot matches the given metadata criteria."""
    import fnmatch
    
    # Handle --without-metadata case
    if metadata_criteria.get("without_metadata", False):
        return not snapshot.metadata
    
    # Handle --with-metadata cases
    with_metadata = metadata_criteria.get("with_metadata", [])
    if not with_metadata or not snapshot.metadata:
        return False
    
    # All criteria must match (AND logic)
    for criterion in with_metadata:
        if "=" in criterion:
            key, value = criterion.split("=", 1)
            if key not in snapshot.metadata:
                return False
            # Support pattern matching
            if any(char in value for char in "*?["):
                if not fnmatch.fnmatch(str(snapshot.metadata[key]), value):
                    return False
            elif str(snapshot.metadata[key]) != value:
                return False
        else:
            # Key existence check
            if criterion not in snapshot.metadata:
                return False
    
    return True


def cleanup_snapshots(client, dry_run: bool = True) -> Dict[str, any]:
    """
    Run snapshot garbage collection and cleanup unreachable snapshots.
    
    This function:
    1. Lists all snapshots and instances from the API
    2. Runs GC analysis to identify unreachable snapshots
    3. Deletes unreachable snapshots (unless dry_run=True)
    4. Returns results with deleted snapshots and any errors
    
    Args:
        client: MorphCloudClient instance
        dry_run: If True, only identifies candidates without deleting
        
    Returns:
        Dict with cleanup results: {"deleted": [...], "errors": [...], "dry_run": bool}
    """
    from morphcloud.api import ApiError
    
    # Fetch all snapshots and instances
    logger.info("Fetching snapshots and instances...")
    snapshots = client.snapshots.list()
    instances = client.instances.list()
    
    logger.info(f"Found {len(snapshots)} snapshots and {len(instances)} instances")
    
    # Run GC analysis
    gc = SnapshotGarbageCollector()
    classification = gc.classify_snapshots(snapshots, instances)
    candidates = gc.get_cleanup_candidates(classification)
    
    logger.info(f"Found {len(candidates)} cleanup candidates")
    
    # Prepare results
    results = {
        "deleted": [],
        "errors": [],
        "dry_run": dry_run,
        "total_snapshots": len(snapshots),
        "gc_roots": len(classification.gc_roots),
        "reachable": len(classification.reachable),
        "unreachable": len(classification.unreachable)
    }
    
    # Process deletion candidates
    for snapshot_id in candidates:
        if dry_run:
            results["deleted"].append(snapshot_id)
            logger.info(f"[DRY RUN] Would delete snapshot: {snapshot_id}")
        else:
            try:
                # Get snapshot object and delete it
                snapshot = client.snapshots.get(snapshot_id)
                snapshot.delete()
                results["deleted"].append(snapshot_id)
                logger.info(f"Deleted snapshot: {snapshot_id}")
            except ApiError as e:
                error_info = {
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                    "status_code": getattr(e, 'status_code', None)
                }
                results["errors"].append(error_info)
                logger.error(f"Failed to delete snapshot {snapshot_id}: {e}")
            except Exception as e:
                error_info = {
                    "snapshot_id": snapshot_id,
                    "error": str(e),
                    "status_code": None
                }
                results["errors"].append(error_info)
                logger.error(f"Unexpected error deleting snapshot {snapshot_id}: {e}")
    
    # Log summary
    if dry_run:
        logger.info(f"[DRY RUN] Would delete {len(results['deleted'])} snapshots")
    else:
        logger.info(f"Deleted {len(results['deleted'])} snapshots, {len(results['errors'])} errors")
    
    return results