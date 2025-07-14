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